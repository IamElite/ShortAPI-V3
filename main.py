# ===============================================
# Shortener API with Encrypted Token Security
# All data encrypted inside token - Nothing visible
# ===============================================

import os
import time
import secrets
import json
import base64
import hashlib
from cryptography.fernet import Fernet
import urllib.request
from urllib.parse import quote
from fastapi import FastAPI, Request, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient

# ================= CONFIGURATION =================
MONGO_URI = os.getenv("MONGO_URI", "mongodb+srv://hnyx:wywyw2@cluster0.9dxlslv.mongodb.net/?retryWrites=true&w=majority")
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "MY_SECRET_PASS_123")
SHORTENER_DOMAIN = os.getenv("SHORTENER_DOMAIN", "nanolinks.in")
SHORTENER_API = os.getenv("SHORTENER_API", "ae0271c2c57105db2fa209f5b0f20c1a965343f6")

# Secret key for encryption - MUST BE 32 BYTES for Fernet
# Generate secure key: base64.urlsafe_b64encode(os.urandom(32))
_secret = os.getenv("ENCRYPTION_SECRET", "MyUltraSecretKey2024XYZ12345678")
# Convert to Fernet-compatible key (32 bytes base64 encoded)
ENCRYPTION_KEY = base64.urlsafe_b64encode(hashlib.sha256(_secret.encode()).digest())

# Link expires after 30 days
LINK_EXPIRY_SECONDS = 30 * 24 * 60 * 60

# ================= DATABASE SETUP =================
client = AsyncIOMotorClient(MONGO_URI)
db = client["shortener_db"]
links_col = db["links"]

async def init_db():
    """Create TTL index for auto-expiry of links"""
    try:
        await links_col.create_index("created_at", expireAfterSeconds=LINK_EXPIRY_SECONDS)
    except:
        pass

app = FastAPI(on_startup=[init_db])

# CORS for API access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# ================= ENCRYPTION FUNCTIONS =================

def encrypt_data(data: dict) -> str:
    """
    Encrypt data into URL-safe token
    Data contains: url, created_at, random_id
    """
    try:
        f = Fernet(ENCRYPTION_KEY)
        json_data = json.dumps(data)
        encrypted = f.encrypt(json_data.encode())
        # Make URL safe
        token = encrypted.decode().replace('+', '-').replace('/', '_').replace('=', '')
        return token
    except Exception as e:
        print(f"Encryption error: {e}")
        return None

def decrypt_data(token: str) -> dict:
    """
    Decrypt token back to data
    Returns None if invalid/tampered
    """
    try:
        # Restore base64 padding
        token = token.replace('-', '+').replace('_', '/')
        padding = 4 - len(token) % 4
        if padding != 4:
            token += '=' * padding
        
        f = Fernet(ENCRYPTION_KEY)
        decrypted = f.decrypt(token.encode())
        data = json.loads(decrypted.decode())
        return data
    except Exception as e:
        # Any error = invalid/tampered token
        return None

def get_base_url(request: Request):
    """Get base URL with HTTPS"""
    url = str(request.base_url).rstrip("/")
    if "localhost" not in url and "127.0.0.1" not in url:
        url = url.replace("http://", "https://")
    return url

# ================= API ENDPOINT (Admin) =================

@app.get("/api")
async def create_link(request: Request, api: str = Query(None), url: str = Query(None)):
    """
    Create a protected short link
    
    Usage: /api?api=YOUR_KEY&url=https://example.com
    
    Returns encrypted token containing all data
    """
    
    # 1. Validate API key
    if api != ADMIN_API_KEY:
        return JSONResponse({"status": "error", "message": "Invalid API Key"}, status_code=403)
    
    if not url:
        return JSONResponse({"status": "error", "message": "URL missing"}, status_code=400)
    
    # 2. Generate unique random ID for this link
    random_id = secrets.token_urlsafe(8)
    
    # 3. Create encrypted token with all data inside
    token_data = {
        "u": url,                    # Original URL (shortened key)
        "t": int(time.time()),       # Created timestamp
        "i": random_id               # Unique ID
    }
    
    encrypted_token = encrypt_data(token_data)
    
    if not encrypted_token:
        return JSONResponse({"status": "error", "message": "Token generation failed"}, status_code=500)
    
    # 4. Save to database for stats (optional, token is self-contained)
    await links_col.update_one(
        {"random_id": random_id},
        {"$set": {
            "random_id": random_id,
            "original_url": url,
            "created_at": time.time(),
            "clicks": 0,
            "bypassed_count": 0
        }},
        upsert=True
    )
    
    # 5. Build redirect URL - Only token visible, nothing else
    base_url = get_base_url(request)
    redirect_url = f"{base_url}/redirect?token={encrypted_token}"
    
    # 6. Shorten via external shortener
    final_url = redirect_url
    
    if SHORTENER_API and SHORTENER_DOMAIN:
        try:
            api_url = f"https://{SHORTENER_DOMAIN}/api?api={SHORTENER_API}&url={quote(redirect_url)}"
            with urllib.request.urlopen(api_url, timeout=10) as resp:
                data = json.loads(resp.read().decode())
                if data.get("status") == "success":
                    final_url = data.get("shortenedUrl", redirect_url)
        except Exception as e:
            print(f"Shortener error: {e}")
    
    return {
        "status": "success",
        "shortenedUrl": final_url,
        "directUrl": redirect_url
    }

# ================= REDIRECT ENDPOINT (User) =================

@app.get("/redirect")
async def redirect_page(request: Request, token: str = Query(None)):
    """
    Redirect with encrypted token verification
    
    Token contains encrypted: url, timestamp, random_id
    If decryption fails = Bypass attempt
    """
    
    if not token:
        return HTMLResponse("""
        <html>
        <head><title>Invalid Link</title></head>
        <body style="text-align:center; padding:50px; font-family:Arial; background:#f5f5f5;">
            <h1 style="color:red;">❌ Invalid Link</h1>
            <p>Token missing or invalid.</p>
        </body>
        </html>
        """, status_code=400)
    
    # 1. Try to decrypt token
    data = decrypt_data(token)
    
    # 2. If decryption failed = Invalid/Tampered/Bypass
    if not data:
        # Try to find any matching partial token in DB for stats
        await links_col.update_one(
            {"random_id": "bypass_attempts"},
            {"$inc": {"bypassed_count": 1}},
            upsert=True
        )
        
        return HTMLResponse("""
        <!DOCTYPE html>
        <html>
        <head>
            <title>⛔ Access Denied</title>
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <style>
                body {
                    font-family: 'Segoe UI', Arial, sans-serif;
                    background: linear-gradient(135deg, #2c3e50 0%, #1a1a2e 100%);
                    min-height: 100vh;
                    margin: 0;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                }
                .container {
                    background: white;
                    padding: 40px;
                    border-radius: 20px;
                    text-align: center;
                    max-width: 420px;
                    box-shadow: 0 20px 60px rgba(0,0,0,0.4);
                }
                h1 { color: #e74c3c; margin-bottom: 10px; }
                p { color: #555; line-height: 1.7; }
                .icon { font-size: 70px; margin-bottom: 20px; }
                .warning-box {
                    background: #fff3cd;
                    border: 1px solid #ffc107;
                    border-radius: 10px;
                    padding: 15px;
                    margin: 20px 0;
                    color: #856404;
                }
                .info { font-size: 13px; color: #888; margin-top: 25px; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="icon">⛔</div>
                <h1>Access Denied!</h1>
                <p>This link is invalid or has been tampered with.</p>
                <div class="warning-box">
                    <strong>⚠️ Security Check Failed</strong><br>
                    Please use the original short link to get access.
                </div>
                <p class="info">If you believe this is a mistake, please request a new link.</p>
            </div>
        </body>
        </html>
        """, status_code=403)
    
    # 3. Token decrypted successfully - Get data
    original_url = data.get("u")
    created_at = data.get("t", 0)
    random_id = data.get("i", "")
    
    # 4. Check if link expired (30 days)
    if time.time() - created_at > LINK_EXPIRY_SECONDS:
        return HTMLResponse("""
        <html>
        <head><title>Link Expired</title></head>
        <body style="text-align:center; padding:50px; font-family:Arial; background:#fff3e0;">
            <h1 style="color:orange;">⏰ Link Expired</h1>
            <p>This link has expired. Please request a new one.</p>
        </body>
        </html>
        """, status_code=410)
    
    # 5. Update click count in database
    if random_id:
        await links_col.update_one(
            {"random_id": random_id},
            {"$inc": {"clicks": 1}}
        )
    
    # 6. SUCCESS - Redirect to original URL
    return HTMLResponse(f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Redirecting...</title>
        <meta http-equiv="refresh" content="0; url={original_url}">
        <style>
            body {{
                font-family: Arial, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                margin: 0;
                display: flex;
                align-items: center;
                justify-content: center;
                color: white;
            }}
        </style>
    </head>
    <body>
        <div>
            <h2>✅ Redirecting...</h2>
            <p>If not redirected, <a href="{original_url}" style="color:white;">click here</a></p>
        </div>
    </body>
    </html>
    """)

# ================= HOME ENDPOINT =================

@app.get("/")
async def home():
    """API Info"""
    return {
        "service": "Shortener API with Encrypted Token Security",
        "version": "4.0",
        "security": "Fernet (AES-128-CBC) Encrypted Tokens",
        "features": [
            "All data encrypted in token",
            "No visible parameters",
            "Tamper-proof verification",
            "Auto-expiry support"
        ],
        "endpoints": {
            "/api?api=KEY&url=URL": "Create protected short link",
            "/redirect?token=XXX": "Secure redirect"
        }
    }

# ================= STATS ENDPOINT =================

@app.get("/stats")
async def stats(api: str = Query(None)):
    """Get link statistics (Admin only)"""
    
    if api != ADMIN_API_KEY:
        return JSONResponse({"status": "error", "message": "Invalid API Key"}, status_code=403)
    
    total_links = await links_col.count_documents({"original_url": {"$exists": True}})
    
    # Get bypass attempts
    bypass_doc = await links_col.find_one({"random_id": "bypass_attempts"})
    bypass_count = bypass_doc.get("bypassed_count", 0) if bypass_doc else 0
    
    # Get top 10 links by clicks
    top_links = await links_col.find({"original_url": {"$exists": True}}).sort("clicks", -1).limit(10).to_list(10)
    
    links_data = []
    for link in top_links:
        links_data.append({
            "id": link.get("random_id", "N/A"),
            "url": link["original_url"][:50] + "..." if len(link["original_url"]) > 50 else link["original_url"],
            "clicks": link.get("clicks", 0)
        })
    
    return {
        "total_links": total_links,
        "bypass_attempts": bypass_count,
        "top_links": links_data
    }
