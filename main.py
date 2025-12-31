# ===============================================
# Shortener API with Multi-Layer Security
# CSRF + Session + IP + Timestamp + Obfuscation
# ===============================================

import os
import time
import secrets
import json
import base64
import hashlib
import hmac
import urllib.request
from urllib.parse import quote
from fastapi import FastAPI, Request, Query, Response
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient

# ================= CONFIGURATION =================
MONGO_URI = os.getenv("MONGO_URI", "mongodb+srv://hnyx:wywyw2@cluster0.9dxlslv.mongodb.net/?retryWrites=true&w=majority")
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "MY_SECRET_PASS_123")
SHORTENER_DOMAIN = os.getenv("SHORTENER_DOMAIN", "nanolinks.in")
SHORTENER_API = os.getenv("SHORTENER_API", "ae0271c2c57105db2fa209f5b0f20c1a965343f6")

# Secret keys - KEEP PRIVATE!
SECRET_KEY = os.getenv("SECRET_KEY", "MyUltraSecretKey2024XYZ!@#$%^&*")
CSRF_SECRET = os.getenv("CSRF_SECRET", "CsrfSecretKey2024!@#")
SESSION_SECRET = os.getenv("SESSION_SECRET", "SessionSecretKey2024!@#")

# Timing settings
LINK_EXPIRY_SECONDS = 30 * 24 * 60 * 60  # 30 days
SESSION_EXPIRY = 300  # 5 minutes
TIMESTAMP_WINDOW = 120  # 2 minutes tolerance

# ================= DATABASE SETUP =================
client = AsyncIOMotorClient(MONGO_URI)
db = client["shortener_db"]
links_col = db["links"]
sessions_col = db["sessions"]

async def init_db():
    """Create indexes"""
    try:
        await links_col.create_index("created_at", expireAfterSeconds=LINK_EXPIRY_SECONDS)
        await sessions_col.create_index("created_at", expireAfterSeconds=SESSION_EXPIRY)
    except:
        pass

app = FastAPI(on_startup=[init_db])

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# ================= SECURITY FUNCTIONS =================

def _get_key(salt: str = "") -> bytes:
    """Generate key from secret + salt"""
    return hashlib.sha256((SECRET_KEY + salt).encode()).digest()

def _xor_encrypt(data: bytes, key: bytes) -> bytes:
    """XOR encryption"""
    return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

def encrypt_token(data: dict) -> str:
    """Encrypt data into URL-safe token"""
    try:
        key = _get_key("token")
        json_data = json.dumps(data, separators=(',', ':'))
        encrypted = _xor_encrypt(json_data.encode(), key)
        b64_data = base64.urlsafe_b64encode(encrypted).decode().rstrip('=')
        signature = hmac.new(key, b64_data.encode(), hashlib.sha256).hexdigest()[:16]
        return f"{b64_data}.{signature}"
    except:
        return None

def decrypt_token(token: str) -> dict:
    """Decrypt token, returns None if invalid"""
    try:
        if '.' not in token:
            return None
        b64_data, signature = token.rsplit('.', 1)
        key = _get_key("token")
        expected_sig = hmac.new(key, b64_data.encode(), hashlib.sha256).hexdigest()[:16]
        if not hmac.compare_digest(signature, expected_sig):
            return None
        padding = 4 - len(b64_data) % 4
        if padding != 4:
            b64_data += '=' * padding
        encrypted = base64.urlsafe_b64decode(b64_data)
        decrypted = _xor_encrypt(encrypted, key)
        return json.loads(decrypted.decode())
    except:
        return None

# ================= CSRF TOKEN =================

def generate_csrf_token(session_id: str, timestamp: int) -> str:
    """Generate CSRF token tied to session and time"""
    data = f"{session_id}:{timestamp}:{CSRF_SECRET}"
    return hashlib.sha256(data.encode()).hexdigest()[:32]

def verify_csrf_token(csrf_token: str, session_id: str, timestamp: int) -> bool:
    """Verify CSRF token"""
    expected = generate_csrf_token(session_id, timestamp)
    return hmac.compare_digest(csrf_token, expected)

# ================= SESSION =================

async def create_session(ip: str, user_agent: str) -> dict:
    """Create new session with all security data"""
    session_id = secrets.token_hex(32)
    timestamp = int(time.time())
    csrf_token = generate_csrf_token(session_id, timestamp)
    obfuscation = secrets.token_urlsafe(8)
    
    # Safety identifier (hash of IP + UA + time)
    safety_hash = hashlib.sha256(f"{ip}:{user_agent}:{timestamp}:{SESSION_SECRET}".encode()).hexdigest()
    
    session_data = {
        "session_id": session_id,
        "csrf_token": csrf_token,
        "timestamp": timestamp,
        "ip": ip,
        "user_agent": user_agent[:200],
        "safety_identifier": safety_hash,
        "obfuscation": obfuscation,
        "created_at": time.time(),
        "used": False
    }
    
    await sessions_col.insert_one(session_data)
    
    return {
        "sid": session_id,
        "csrf": csrf_token,
        "ts": timestamp,
        "obf": obfuscation,
        "safety": safety_hash[:16]  # Only show partial for client
    }

async def validate_session(session_id: str, csrf_token: str, timestamp: int, 
                           ip: str, user_agent: str, safety: str) -> dict:
    """Validate session with all security checks"""
    
    # 1. Find session
    session = await sessions_col.find_one({
        "session_id": session_id,
        "used": False
    })
    
    if not session:
        return {"valid": False, "reason": "Session not found or expired"}
    
    # 2. Verify CSRF token
    if not verify_csrf_token(csrf_token, session_id, session["timestamp"]):
        return {"valid": False, "reason": "Invalid CSRF token"}
    
    # 3. Timestamp validation (anti-replay)
    time_diff = abs(int(time.time()) - timestamp)
    if time_diff > TIMESTAMP_WINDOW:
        return {"valid": False, "reason": "Timestamp expired"}
    
    # 4. IP validation
    if session["ip"] != ip:
        return {"valid": False, "reason": "IP mismatch"}
    
    # 5. Safety identifier check
    expected_safety = session["safety_identifier"][:16]
    if not hmac.compare_digest(safety, expected_safety):
        return {"valid": False, "reason": "Safety check failed"}
    
    return {"valid": True, "session": session}

def get_base_url(request: Request):
    """Get base URL with HTTPS"""
    url = str(request.base_url).rstrip("/")
    if "localhost" not in url and "127.0.0.1" not in url:
        url = url.replace("http://", "https://")
    return url

def get_client_info(request: Request) -> dict:
    """Extract client info for fingerprinting"""
    ip = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
    if not ip:
        ip = request.headers.get("X-Real-IP", "")
    if not ip:
        ip = request.client.host if request.client else "unknown"
    
    return {
        "ip": ip,
        "user_agent": request.headers.get("User-Agent", "")[:200],
        "country": request.headers.get("CF-IPCountry", "XX")
    }

# ================= API ENDPOINT (Admin) =================

@app.get("/api")
async def create_link(request: Request, api: str = Query(None), url: str = Query(None)):
    """Create protected short link"""
    
    if api != ADMIN_API_KEY:
        return JSONResponse({"status": "error", "message": "Invalid API Key"}, status_code=403)
    
    if not url:
        return JSONResponse({"status": "error", "message": "URL missing"}, status_code=400)
    
    random_id = secrets.token_urlsafe(8)
    
    # Token contains only the link ID - session handles security
    token_data = {
        "i": random_id,              # Link ID
        "t": int(time.time()),       # Created timestamp
    }
    
    encrypted_token = encrypt_token(token_data)
    
    if not encrypted_token:
        return JSONResponse({"status": "error", "message": "Token generation failed"}, status_code=500)
    
    # Save link data in DB
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
    
    base_url = get_base_url(request)
    redirect_url = f"{base_url}/redirect?token={encrypted_token}"
    
    # Shorten via external shortener
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

# ================= REDIRECT PAGE (Step 1: Show verification page) =================

@app.get("/redirect")
async def redirect_page(request: Request, token: str = Query(None)):
    """
    Step 1: Show verification page with all security tokens
    Creates session, CSRF, timestamp, obfuscation - all in background
    """
    
    if not token:
        return HTMLResponse("<h1>Invalid Link</h1>", status_code=400)
    
    # Decrypt token
    data = decrypt_token(token)
    
    if not data:
        await links_col.update_one(
            {"random_id": "bypass_attempts"},
            {"$inc": {"bypassed_count": 1}},
            upsert=True
        )
        return HTMLResponse("""
        <!DOCTYPE html>
        <html>
        <head><title>Access Denied</title>
        <style>
            body{font-family:Arial;background:#1a1a2e;color:white;display:flex;
            align-items:center;justify-content:center;height:100vh;margin:0;}
            .box{background:#2d2d44;padding:40px;border-radius:15px;text-align:center;}
            h1{color:#e74c3c;}
        </style>
        </head>
        <body><div class="box">
            <h1>⛔ Access Denied</h1>
            <p>Invalid or tampered link.</p>
        </div></body>
        </html>
        """, status_code=403)
    
    random_id = data.get("i")
    created_at = data.get("t", 0)
    
    # Check link expiry
    if time.time() - created_at > LINK_EXPIRY_SECONDS:
        return HTMLResponse("<h1>⏰ Link Expired</h1>", status_code=410)
    
    # Get link from DB
    link = await links_col.find_one({"random_id": random_id})
    if not link:
        return HTMLResponse("<h1>Link Not Found</h1>", status_code=404)
    
    # Create session with all security data
    client = get_client_info(request)
    session = await create_session(client["ip"], client["user_agent"])
    
    # Store link info in session for step 2
    await sessions_col.update_one(
        {"session_id": session["sid"]},
        {"$set": {"link_id": random_id}}
    )
    
    # Return page with hidden security tokens - JavaScript will submit
    return HTMLResponse(f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Security Verification</title>
        <meta name="viewport" content="width=device-width,initial-scale=1">
        <style>
            body{{font-family:'Segoe UI',Arial;background:linear-gradient(135deg,#667eea,#764ba2);
            min-height:100vh;margin:0;display:flex;align-items:center;justify-content:center;}}
            .card{{background:white;padding:40px;border-radius:20px;text-align:center;
            max-width:400px;box-shadow:0 20px 60px rgba(0,0,0,0.3);}}
            h1{{color:#333;margin-bottom:10px;}}
            p{{color:#666;}}
            .loader{{width:50px;height:50px;border:5px solid #e0e0e0;border-top:5px solid #667eea;
            border-radius:50%;animation:spin 1s linear infinite;margin:20px auto;}}
            @keyframes spin{{0%{{transform:rotate(0deg)}}100%{{transform:rotate(360deg)}}}}
            .status{{font-size:14px;color:#888;margin-top:15px;}}
        </style>
    </head>
    <body>
        <div class="card">
            <h1>🔐 Verifying...</h1>
            <p>Please wait while we verify your access.</p>
            <div class="loader"></div>
            <div class="status" id="status">Checking security...</div>
        </div>
        
        <script>
            // All security data - hidden from user
            const SEC = {{
                sid: "{session['sid']}",
                csrf: "{session['csrf']}",
                ts: {session['ts']},
                obf: "{session['obf']}",
                safety: "{session['safety']}",
                token: "{token}"
            }};
            
            // IP info from client
            const ipInfo = {{
                ip: "{client['ip']}",
                country: "{client['country']}"
            }};
            
            // Send verification after small delay (anti-bot)
            setTimeout(async () => {{
                document.getElementById('status').innerText = 'Validating session...';
                
                try {{
                    const response = await fetch('/verify', {{
                        method: 'POST',
                        headers: {{
                            'Content-Type': 'application/json',
                            'X-CSRF-TOKEN': SEC.csrf,
                            'X-Session-ID': SEC.sid,
                            'X-Timestamp': SEC.ts.toString(),
                            'X-Safety': SEC.safety,
                            'X-Obfuscation': SEC.obf
                        }},
                        body: JSON.stringify({{
                            token: SEC.token,
                            timestamp: Date.now(),
                            ipInfo: ipInfo
                        }})
                    }});
                    
                    const result = await response.json();
                    
                    if (result.success) {{
                        document.getElementById('status').innerText = '✅ Verified! Redirecting...';
                        setTimeout(() => {{
                            window.location.href = result.destination;
                        }}, 500);
                    }} else {{
                        document.getElementById('status').innerText = '❌ ' + result.message;
                    }}
                }} catch (e) {{
                    document.getElementById('status').innerText = '❌ Verification failed';
                }}
            }}, 1500);
        </script>
    </body>
    </html>
    """)

# ================= VERIFY ENDPOINT (Step 2: Validate everything) =================

@app.post("/verify")
async def verify_redirect(request: Request):
    """
    Step 2: Validate all security tokens and redirect
    Checks: Session, CSRF, Timestamp, IP, Safety ID
    """
    
    try:
        # Get headers
        csrf_token = request.headers.get("X-CSRF-TOKEN", "")
        session_id = request.headers.get("X-Session-ID", "")
        timestamp = int(request.headers.get("X-Timestamp", "0"))
        safety = request.headers.get("X-Safety", "")
        obfuscation = request.headers.get("X-Obfuscation", "")
        
        # Get body
        body = await request.json()
        token = body.get("token", "")
        client_timestamp = body.get("timestamp", 0)
        
        # Get client info
        client = get_client_info(request)
        
        # Validate session with all checks
        validation = await validate_session(
            session_id, csrf_token, timestamp,
            client["ip"], client["user_agent"], safety
        )
        
        if not validation["valid"]:
            await links_col.update_one(
                {"random_id": "bypass_attempts"},
                {"$inc": {"bypassed_count": 1}},
                upsert=True
            )
            return JSONResponse({
                "success": False,
                "message": validation["reason"]
            }, status_code=403)
        
        session = validation["session"]
        
        # Verify obfuscation key
        if session.get("obfuscation") != obfuscation:
            return JSONResponse({
                "success": False,
                "message": "Obfuscation mismatch"
            }, status_code=403)
        
        # Mark session as used (one-time)
        result = await sessions_col.update_one(
            {"session_id": session_id, "used": False},
            {"$set": {"used": True, "used_at": time.time()}}
        )
        
        if result.modified_count == 0:
            return JSONResponse({
                "success": False,
                "message": "Session already used"
            }, status_code=403)
        
        # Get original URL
        link_id = session.get("link_id")
        link = await links_col.find_one({"random_id": link_id})
        
        if not link:
            return JSONResponse({
                "success": False,
                "message": "Link not found"
            }, status_code=404)
        
        # Update click count
        await links_col.update_one(
            {"random_id": link_id},
            {"$inc": {"clicks": 1}}
        )
        
        # SUCCESS!
        return JSONResponse({
            "success": True,
            "destination": link["original_url"]
        })
        
    except Exception as e:
        print(f"Verify error: {e}")
        return JSONResponse({
            "success": False,
            "message": "Verification failed"
        }, status_code=500)

# ================= HOME =================

@app.get("/")
async def home():
    return {
        "service": "Shortener API with Multi-Layer Security",
        "version": "5.0",
        "security": [
            "CSRF Tokens",
            "Session IDs (Server-validated)",
            "Safety Identifiers (Hash-based)",
            "Timestamp Validation",
            "IP Fingerprinting",
            "Response Obfuscation",
            "One-time Sessions"
        ],
        "endpoints": {
            "/api?api=KEY&url=URL": "Create link",
            "/redirect?token=XXX": "Verify page",
            "/verify": "Backend validation"
        }
    }

# ================= STATS =================

@app.get("/stats")
async def stats(api: str = Query(None)):
    if api != ADMIN_API_KEY:
        return JSONResponse({"status": "error", "message": "Invalid API Key"}, status_code=403)
    
    total_links = await links_col.count_documents({"original_url": {"$exists": True}})
    bypass_doc = await links_col.find_one({"random_id": "bypass_attempts"})
    bypass_count = bypass_doc.get("bypassed_count", 0) if bypass_doc else 0
    active_sessions = await sessions_col.count_documents({"used": False})
    used_sessions = await sessions_col.count_documents({"used": True})
    
    # Calculate approximate storage
    stats_data = await db.command("dbStats")
    storage_mb = round(stats_data.get("dataSize", 0) / (1024 * 1024), 2)
    
    return {
        "total_links": total_links,
        "bypass_attempts": bypass_count,
        "active_sessions": active_sessions,
        "used_sessions": used_sessions,
        "storage_mb": storage_mb,
        "storage_limit_mb": 500
    }

# ================= CLEANUP ENDPOINT =================

@app.get("/cleanup")
async def cleanup_db(api: str = Query(None)):
    """
    Manual cleanup - Delete old data to save storage
    Free plan = 500MB, so aggressive cleanup needed
    """
    if api != ADMIN_API_KEY:
        return JSONResponse({"status": "error", "message": "Invalid API Key"}, status_code=403)
    
    now = time.time()
    
    # 1. Delete used sessions (older than 1 minute)
    used_result = await sessions_col.delete_many({
        "used": True,
        "used_at": {"$lt": now - 60}
    })
    
    # 2. Delete expired sessions (older than 5 minutes)
    expired_result = await sessions_col.delete_many({
        "created_at": {"$lt": now - SESSION_EXPIRY}
    })
    
    # 3. Delete old links (older than 7 days to save space)
    old_links_result = await links_col.delete_many({
        "original_url": {"$exists": True},
        "created_at": {"$lt": now - (7 * 24 * 60 * 60)}  # 7 days
    })
    
    # 4. Delete links with 0 clicks older than 1 day
    unused_result = await links_col.delete_many({
        "original_url": {"$exists": True},
        "clicks": 0,
        "created_at": {"$lt": now - (24 * 60 * 60)}  # 1 day
    })
    
    return {
        "status": "success",
        "deleted": {
            "used_sessions": used_result.deleted_count,
            "expired_sessions": expired_result.deleted_count,
            "old_links_7d": old_links_result.deleted_count,
            "unused_links_1d": unused_result.deleted_count
        },
        "message": "Cleanup completed"
    }

# ================= AUTO CLEANUP ON STARTUP =================

@app.on_event("startup")
async def startup_cleanup():
    """Run cleanup on every server start"""
    try:
        now = time.time()
        # Quick cleanup of sessions
        await sessions_col.delete_many({"created_at": {"$lt": now - SESSION_EXPIRY}})
        await sessions_col.delete_many({"used": True})
        print("Startup cleanup completed")
    except Exception as e:
        print(f"Startup cleanup error: {e}")
