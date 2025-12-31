# ===============================================
# Simple Shortener API with Bypass Detection
# ===============================================

import os
import time
import secrets
import json
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

# ================= HELPER FUNCTIONS =================

def generate_token(length=12):
    """Generate secure random token"""
    return secrets.token_urlsafe(length)

def get_base_url(request: Request):
    """Get base URL with HTTPS"""
    url = str(request.base_url).rstrip("/")
    if "localhost" not in url and "127.0.0.1" not in url:
        url = url.replace("http://", "https://")
    return url

def check_bypass(referer: str, shortener_domain: str):
    """
    Check if user bypassed the shortener
    Returns: (bypassed: bool, reason: str)
    """
    if not referer:
        return True, "No referer - Direct access or bypassed"
    
    referer_lower = referer.lower()
    
    # Check if came from shortener domain
    if shortener_domain.lower() in referer_lower:
        return False, "Came from shortener"
    
    # Common bypass indicators
    bypass_keywords = ["bypass", "skip", "direct", "adfree"]
    if any(kw in referer_lower for kw in bypass_keywords):
        return True, "Bypass site detected in referer"
    
    return True, f"Unknown referer: {referer}"

# ================= API ENDPOINT (Admin) =================

@app.get("/api")
async def create_link(request: Request, api: str = Query(None), url: str = Query(None)):
    """
    Create a protected short link
    
    Usage: /api?api=YOUR_KEY&url=https://example.com
    """
    
    # 1. Validate API key
    if api != ADMIN_API_KEY:
        return JSONResponse({"status": "error", "message": "Invalid API Key"}, status_code=403)
    
    if not url:
        return JSONResponse({"status": "error", "message": "URL missing"}, status_code=400)
    
    # 2. Check if URL already exists
    existing = await links_col.find_one({"original_url": url})
    
    if existing:
        token = existing["token"]
        # Refresh expiry
        await links_col.update_one(
            {"_id": existing["_id"]}, 
            {"$set": {"created_at": time.time()}}
        )
    else:
        # 3. Create new link
        token = generate_token()
        await links_col.insert_one({
            "token": token,
            "original_url": url,
            "created_at": time.time(),
            "clicks": 0,
            "bypassed_count": 0
        })
    
    # 4. Build redirect URL
    base_url = get_base_url(request)
    redirect_url = f"{base_url}/redirect?token={token}"
    
    # 5. Shorten via external shortener
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
        "directUrl": redirect_url,
        "token": token
    }

# ================= REDIRECT ENDPOINT (User) =================

@app.get("/redirect")
async def redirect_page(request: Request, token: str = Query(None)):
    """
    Redirect page with bypass detection
    
    User clicks short link → Shortener → This page → Original URL
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
    
    # 1. Find link in database
    link = await links_col.find_one({"token": token})
    
    if not link:
        return HTMLResponse("""
        <html>
        <head><title>Link Expired</title></head>
        <body style="text-align:center; padding:50px; font-family:Arial; background:#fff3e0;">
            <h1 style="color:orange;">⏰ Link Expired</h1>
            <p>This link has expired or does not exist.</p>
        </body>
        </html>
        """, status_code=404)
    
    # 2. Check for bypass
    referer = request.headers.get("Referer", "")
    bypassed, reason = check_bypass(referer, SHORTENER_DOMAIN)
    
    original_url = link["original_url"]
    
    # 3. Update stats
    if bypassed:
        await links_col.update_one(
            {"_id": link["_id"]},
            {"$inc": {"bypassed_count": 1, "clicks": 1}}
        )
    else:
        await links_col.update_one(
            {"_id": link["_id"]},
            {"$inc": {"clicks": 1}}
        )
    
    # 4. If bypassed - show warning page, else redirect
    if bypassed:
        return HTMLResponse(f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>⚠️ Bypass Detected</title>
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <style>
                body {{
                    font-family: 'Segoe UI', Arial, sans-serif;
                    background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%);
                    min-height: 100vh;
                    margin: 0;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                }}
                .container {{
                    background: white;
                    padding: 40px;
                    border-radius: 20px;
                    text-align: center;
                    max-width: 400px;
                    box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                }}
                h1 {{ color: #e74c3c; margin-bottom: 10px; }}
                p {{ color: #666; line-height: 1.6; }}
                .warning {{ font-size: 60px; margin-bottom: 20px; }}
                .btn {{
                    display: inline-block;
                    margin-top: 20px;
                    padding: 15px 30px;
                    background: #e74c3c;
                    color: white;
                    text-decoration: none;
                    border-radius: 10px;
                    font-weight: bold;
                }}
                .btn:hover {{ background: #c0392b; }}
                .small {{ font-size: 12px; color: #999; margin-top: 20px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="warning">⚠️</div>
                <h1>Bypass Detected!</h1>
                <p>You tried to skip the advertisement. Please use the original short link to support us.</p>
                <p class="small">Reason: {reason}</p>
                <a href="{original_url}" class="btn">Continue Anyway →</a>
            </div>
        </body>
        </html>
        """)
    
    # 5. No bypass - Direct redirect
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
        "service": "Shortener API with Bypass Detection",
        "version": "2.0",
        "endpoints": {
            "/api?api=KEY&url=URL": "Create protected short link",
            "/redirect?token=XXX": "Redirect with bypass check"
        }
    }

# ================= STATS ENDPOINT =================

@app.get("/stats")
async def stats(api: str = Query(None)):
    """Get link statistics (Admin only)"""
    
    if api != ADMIN_API_KEY:
        return JSONResponse({"status": "error", "message": "Invalid API Key"}, status_code=403)
    
    total_links = await links_col.count_documents({})
    
    # Get top 10 links by clicks
    top_links = await links_col.find().sort("clicks", -1).limit(10).to_list(10)
    
    links_data = []
    for link in top_links:
        links_data.append({
            "token": link["token"],
            "url": link["original_url"][:50] + "..." if len(link["original_url"]) > 50 else link["original_url"],
            "clicks": link.get("clicks", 0),
            "bypassed": link.get("bypassed_count", 0)
        })
    
    return {
        "total_links": total_links,
        "top_links": links_data
    }
