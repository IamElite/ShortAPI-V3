# ===============================================
# Shortener API with Multi-Layer Reinforced Security
# 5s Wait + JS Challenge + CSRF + Fingerprinting
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
CHALLENGE_SECRET = os.getenv("CHALLENGE_SECRET", "ChallengeSecretKey2024!@#")

# Timing settings
LINK_EXPIRY_SECONDS = 30 * 24 * 60 * 60  # 30 days
SESSION_EXPIRY = 600  # 10 minutes
MIN_WAIT_SECONDS = 5  # MUST WAIT AT LEAST 5 SECONDS (Anti-Bypass)

# ================= DATABASE SETUP =================
client = AsyncIOMotorClient(MONGO_URI)
db = client["shortener_db"]
links_col = db["links"]
sessions_col = db["sessions"]

async def init_db():
    """Create indexes for performance and auto-cleanup"""
    try:
        await links_col.create_index("created_at", expireAfterSeconds=LINK_EXPIRY_SECONDS)
        await sessions_col.create_index("created_at", expireAfterSeconds=SESSION_EXPIRY)
        await links_col.create_index("random_id", unique=True)
        await sessions_col.create_index("session_id", unique=True)
    except:
        pass

app = FastAPI(on_startup=[init_db])

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# ================= ENCRYPTION & SECURITY HELPERS =================

def _get_key(salt: str = "") -> bytes:
    return hashlib.sha256((SECRET_KEY + salt).encode()).digest()

def _xor_cipher(data: bytes, key: bytes) -> bytes:
    return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

def encrypt_token(data: dict) -> str:
    try:
        key = _get_key("token")
        json_data = json.dumps(data, separators=(',', ':'))
        encrypted = _xor_cipher(json_data.encode(), key)
        b64_data = base64.urlsafe_b64encode(encrypted).decode().rstrip('=')
        signature = hmac.new(key, b64_data.encode(), hashlib.sha256).hexdigest()[:16]
        return f"{b64_data}.{signature}"
    except: return None

def decrypt_token(token: str) -> dict:
    try:
        b64_data, signature = token.rsplit('.', 1)
        key = _get_key("token")
        if not hmac.compare_digest(signature, hmac.new(key, b64_data.encode(), hashlib.sha256).hexdigest()[:16]):
            return None
        padding = 4 - len(b64_data) % 4
        if padding != 4: b64_data += '=' * padding
        decrypted = _xor_cipher(base64.urlsafe_b64decode(b64_data), key)
        return json.loads(decrypted.decode())
    except: return None

# ================= CHALLENGE LOGIC =================

def generate_challenge(session_id: str) -> tuple[str, str]:
    """Generates a dynamic math challenge that JS must solve"""
    n1 = secrets.randbelow(100) + 1
    n2 = secrets.randbelow(100) + 1
    # Simple challenge: (n1 * n2) + hash(session_id + secret)
    salt = hashlib.md5(f"{session_id}:{CHALLENGE_SECRET}".encode()).hexdigest()[:8]
    # We send the expression and require the result
    challenge_expr = f"({n1} * {n2}) + parseInt('{salt}', 16)"
    expected_result = (n1 * n2) + int(salt, 16)
    return challenge_expr, str(expected_result)

# ================= SESSION MANAGEMENT =================

async def create_secure_session(request: Request, link_id: str) -> dict:
    session_id = secrets.token_hex(24)
    ip = request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or request.client.host
    ua = request.headers.get("User-Agent", "")[:250]
    
    challenge_expr, expected_val = generate_challenge(session_id)
    csrf_token = secrets.token_urlsafe(32)
    
    session_data = {
        "session_id": session_id,
        "link_id": link_id,
        "ip": ip,
        "ua": ua,
        "csrf": csrf_token,
        "challenge_ans": expected_val,
        "created_at": time.time(),
        "used": False
    }
    
    await sessions_col.insert_one(session_data)
    return {
        "sid": session_id,
        "csrf": csrf_token,
        "expr": challenge_expr
    }

# ================= API ENDPOINT (Admin) =================

@app.get("/api")
async def create_link(request: Request, api: str = Query(None), url: str = Query(None)):
    if api != ADMIN_API_KEY:
        return JSONResponse({"status": "error", "message": "Invalid API Key"}, status_code=403)
    if not url:
        return JSONResponse({"status": "error", "message": "URL missing"}, status_code=400)
    
    random_id = secrets.token_urlsafe(8)
    token = encrypt_token({"i": random_id, "t": int(time.time())})
    
    await links_col.update_one(
        {"random_id": random_id},
        {"$set": {"original_url": url, "created_at": time.time(), "clicks": 0}},
        upsert=True
    )
    
    base_url = str(request.base_url).rstrip("/")
    if "localhost" not in base_url: base_url = base_url.replace("http://", "https://")
    redirect_url = f"{base_url}/redirect?token={token}"
    
    final_url = redirect_url
    if SHORTENER_API:
        try:
            api_url = f"https://{SHORTENER_DOMAIN}/api?api={SHORTENER_API}&url={quote(redirect_url)}"
            with urllib.request.urlopen(api_url, timeout=10) as resp:
                data = json.loads(resp.read().decode())
                if data.get("status") == "success":
                    final_url = data.get("shortenedUrl", redirect_url)
        except: pass
        
    return {"status": "success", "shortenedUrl": final_url, "token": token}

# ================= REDIRECT FLOW =================

@app.get("/redirect")
async def handle_redirect(request: Request, token: str = Query(None)):
    if not token: return HTMLResponse("<h1>Invalid Token</h1>", status_code=400)
    data = decrypt_token(token)
    if not data: return HTMLResponse("<h1>Link Corrupted</h1>", status_code=403)
    
    link = await links_col.find_one({"random_id": data.get("i")})
    if not link: return HTMLResponse("<h1>Link Expired</h1>", status_code=404)
    
    session = await create_secure_session(request, data.get("i"))
    
    return HTMLResponse(f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Security Check</title>
        <style>
            body {{ font-family: 'Inter', sans-serif; background: #0f172a; color: #f8fafc; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }}
            .card {{ background: #1e293b; padding: 2.5rem; border-radius: 1.5rem; box-shadow: 0 25px 50px -12px rgba(0,0,0,0.5); text-align: center; max-width: 400px; width: 90%; border: 1px solid #334155; }}
            .shield {{ font-size: 3rem; color: #38bdf8; margin-bottom: 1rem; }}
            h1 {{ font-size: 1.5rem; margin-bottom: 0.5rem; }}
            p {{ color: #94a3b8; font-size: 0.9rem; line-height: 1.5; }}
            .loader {{ width: 2.5rem; height: 2.5rem; border: 4px solid #334155; border-top-color: #38bdf8; border-radius: 50%; animation: spin 0.8s linear infinite; margin: 1.5rem auto; }}
            @keyframes spin {{ to {{ transform: rotate(360deg); }} }}
            .progress {{ font-size: 0.8rem; color: #38bdf8; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; }}
        </style>
    </head>
    <body>
        <div class="card">
            <div class="shield">🛡️</div>
            <h1>Bypass Protection</h1>
            <p>We are verifying your connection. This takes exactly {MIN_WAIT_SECONDS} seconds to prevent automated bypass.</p>
            <div class="loader"></div>
            <div class="progress" id="status">Starting Security Protocol...</div>
        </div>

        <script>
            const CONFIG = {{
                sid: "{session['sid']}",
                csrf: "{session['csrf']}",
                token: "{token}",
                wait: {MIN_WAIT_SECONDS} * 1000
            }};

            async function solveChallenge() {{
                try {{
                    // Solving dynamic challenge that bots cannot easily replicate
                    return eval("{session['expr']}");
                }} catch(e) {{ return 0; }}
            }}

            let startTime = Date.now();
            
            async function verify() {{
                const elapsed = Date.now() - startTime;
                if (elapsed < CONFIG.wait) {{
                    document.getElementById('status').innerText = "Anti-Bot Delay: Waiting...";
                    setTimeout(verify, 500);
                    return;
                }}

                document.getElementById('status').innerText = "Executing JS Challenge...";
                const ans = await solveChallenge();
                
                // Fingerprinting check
                const isBot = navigator.webdriver || window.callPhantom || window._phantom || !navigator.userAgent;

                try {{
                    const res = await fetch('/verify', {{
                        method: 'POST',
                        headers: {{ 'Content-Type': 'application/json', 'X-CSRF-Token': CONFIG.csrf }},
                        body: JSON.stringify({{
                            sid: CONFIG.sid,
                            token: CONFIG.token,
                            ans: ans.toString(),
                            bot: isBot
                        }})
                    }});
                    const data = await res.json();
                    if (data.success) {{
                        document.getElementById('status').innerText = "Verified! Redirecting...";
                        window.location.href = data.url;
                    }} else {{
                        document.getElementById('status').innerText = "⛔ Access Denied: " + data.message;
                    }}
                }} catch(e) {{
                    document.getElementById('status').innerText = "⚠️ Network Error. Try again.";
                }}
            }}

            setTimeout(verify, 1000);
        </script>
    </body>
    </html>
    """)

@app.post("/verify")
async def verify_request(request: Request):
    try:
        body = await request.json()
        sid = body.get("sid")
        ans = body.get("ans")
        is_bot_client = body.get("bot", False)
        csrf_header = request.headers.get("X-CSRF-Token")
        
        # 1. Basic validation
        if is_bot_client: return JSONResponse({"success":False, "message": "Automation tool detected"}, 403)
        
        # 2. Get session
        session = await sessions_col.find_one({ "session_id": sid, "used": False })
        if not session: return JSONResponse({"success":False, "message": "Session expired or invalid"}, 403)
        
        # 3. Security Checks
        now = time.time()
        # Strictly enforce wait time
        if now - session["created_at"] < MIN_WAIT_SECONDS:
             return JSONResponse({"success":False, "message": "Verification too fast. Bot behavior detected."}, 403)
        
        # CSRF Check
        if not hmac.compare_digest(session["csrf"], csrf_header or ""):
             return JSONResponse({"success":False, "message": "CSRF verification failed"}, 403)
        
        # Challenge Answer Check
        if not hmac.compare_digest(session["challenge_ans"], ans or ""):
             return JSONResponse({"success":False, "message": "JS challenge failed"}, 403)
             
        # IP/UA Check
        ip = request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or request.client.host
        if session["ip"] != ip:
             return JSONResponse({"success":False, "message": "IP address changed mid-session"}, 403)
        
        # 4. Success - Mark used and redirect
        await sessions_col.update_one({"session_id": sid}, {"$set": {"used": True, "used_at": now}})
        
        link = await links_col.find_one({"random_id": session["link_id"]})
        if not link: return JSONResponse({"success":False, "message": "Link not found"}, 404)
        
        await links_col.update_one({"random_id": session["link_id"]}, {"$inc": {"clicks": 1}})
        
        return {"success": True, "url": link["original_url"]}
        
    except Exception as e:
        return JSONResponse({"success":False, "message": "System Error"}, 500)

# ================= HOUSEKEEPING =================

@app.get("/stats")
async def get_stats(api: str = Query(None)):
    if api != ADMIN_API_KEY: return JSONResponse({"status":"error"}, 403)
    c_links = await links_col.count_documents({})
    c_sess = await sessions_col.count_documents({})
    return {"total_links": c_links, "active_sessions": c_sess}

@app.get("/cleanup")
async def cleanup(api: str = Query(None)):
    if api != ADMIN_API_KEY: return JSONResponse({"status":"error"}, 403)
    now = time.time()
    await sessions_col.delete_many({"$or": [{"used": True}, {"created_at": {"$lt": now - SESSION_EXPIRY}}]})
    await links_col.delete_many({"created_at": {"$lt": now - LINK_EXPIRY_SECONDS}})
    return {"status": "success"}

@app.on_event("startup")
async def on_start():
    await init_db()
    # Auto cleanup sessions on start
    await sessions_col.delete_many({})
    print("Security System Online")
