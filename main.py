# ===============================================
# Shortener API - ULTRA REINFORCED SECURITY v6.1
# Strict Referer + Session Lock + JS Challenge
# ===============================================

import os
import time
import secrets
import json
import base64
import hashlib
import hmac
import urllib.request
from urllib.parse import quote, urlparse
from fastapi import FastAPI, Request, Query, Response
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient

# ================= CONFIGURATION =================
MONGO_URI = os.getenv("MONGO_URI", "mongodb+srv://hnyx:wywyw2@cluster0.9dxlslv.mongodb.net/?retryWrites=true&w=majority")
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "MY_SECRET_PASS_123")
SHORTENER_DOMAIN = os.getenv("SHORTENER_DOMAIN", "nanolinks.in")
SHORTENER_API = os.getenv("SHORTENER_API", "ae0271c2c57105db2fa209f5b0f20c1a965343f6")

# Secret keys
SECRET_KEY = os.getenv("SECRET_KEY", "AlphaOmegaSecurity2025!@#")
CHALLENGE_SECRET = os.getenv("CHALLENGE_SECRET", "OmegaChallenge2025!@#")

# Timing
LINK_EXPIRY_SECONDS = 30 * 24 * 60 * 60
SESSION_EXPIRY = 600

# ================= DATABASE SETUP =================
client = AsyncIOMotorClient(MONGO_URI)
db = client["shortener_db"]
links_col = db["links"]
sessions_col = db["sessions"]

async def init_db():
    try:
        await links_col.create_index("created_at", expireAfterSeconds=LINK_EXPIRY_SECONDS)
        await sessions_col.create_index("created_at", expireAfterSeconds=SESSION_EXPIRY)
        await links_col.create_index("random_id", unique=True)
    except: pass

app = FastAPI(on_startup=[init_db])

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# ================= CRYPTO HELPERS =================

def _get_key(salt: str = "") -> bytes:
    return hashlib.sha256((SECRET_KEY + salt).encode()).digest()

def _xor_cipher(data: bytes, key: bytes) -> bytes:
    return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

def encrypt_token(data: dict) -> str:
    try:
        key = _get_key("token")
        json_data = json.dumps(data, separators=(',', ':'))
        encrypted = _xor_cipher(json_data.encode(), key)
        b64 = base64.urlsafe_b64encode(encrypted).decode().rstrip('=')
        sig = hmac.new(key, b64.encode(), hashlib.sha256).hexdigest()[:16]
        return f"{b64}.{sig}"
    except: return None

def decrypt_token(token: str) -> dict:
    try:
        b64, sig = token.rsplit('.', 1)
        key = _get_key("token")
        if not hmac.compare_digest(sig, hmac.new(key, b64.encode(), hashlib.sha256).hexdigest()[:16]): return None
        pad = 4 - len(b64) % 4
        if pad != 4: b64 += '=' * pad
        dec = _xor_cipher(base64.urlsafe_b64decode(b64), key)
        return json.loads(dec.decode())
    except: return None

# ================= SECURITY LOGIC =================

def check_referer_is_valid(referer: str) -> bool:
    """Strictly checks if the request is coming from the shortener"""
    if not referer: return False
    parsed = urlparse(referer)
    domain = parsed.netloc.lower()
    return SHORTENER_DOMAIN.lower() in domain

async def create_secure_session(request: Request, link_id: str) -> dict:
    session_id = secrets.token_hex(32)
    referer = request.headers.get("referer", "")
    ip = request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or request.client.host
    ua = request.headers.get("User-Agent", "")[:250]
    
    # Check for bypass at entry point
    is_bypassed = not check_referer_is_valid(referer)
    
    # Generate JS Challenge
    n1, n2 = secrets.randbelow(100)+1, secrets.randbelow(100)+1
    salt = hashlib.md5(f"{session_id}:{CHALLENGE_SECRET}".encode()).hexdigest()[:8]
    expr = f"({n1} * {n2}) + parseInt('{salt}', 16)"
    ans = str((n1 * n2) + int(salt, 16))
    
    csrf = secrets.token_urlsafe(32)
    
    session_data = {
        "session_id": session_id,
        "link_id": link_id,
        "ip": ip,
        "ua": ua,
        "csrf": csrf,
        "ans": ans,
        "is_bypassed": is_bypassed,
        "created_at": time.time(),
        "used": False
    }
    
    await sessions_col.insert_one(session_data)
    return {"sid": session_id, "csrf": csrf, "expr": expr}

# ================= ROUTES =================

@app.get("/api")
async def create_link(request: Request, api: str = Query(None), url: str = Query(None)):
    if api != ADMIN_API_KEY: return JSONResponse({"status":"error","message":"Auth Fail"}, 403)
    if not url: return JSONResponse({"status":"error","message":"No URL"}, 400)
    
    rid = secrets.token_urlsafe(8)
    token = encrypt_token({"i": rid, "t": int(time.time())})
    
    await links_col.update_one({"random_id": rid}, {"$set": {"original_url": url, "created_at": time.time(), "clicks": 0}}, upsert=True)
    
    base = str(request.base_url).rstrip("/")
    if "localhost" not in base: base = base.replace("http://", "https://")
    red_url = f"{base}/redirect?token={token}"
    
    final = red_url
    if SHORTENER_API:
        try:
            req_url = f"https://{SHORTENER_DOMAIN}/api?api={SHORTENER_API}&url={quote(red_url)}"
            with urllib.request.urlopen(req_url, timeout=5) as r:
                d = json.loads(r.read().decode())
                if d.get("status") == "success": final = d.get("shortenedUrl")
        except: pass
    return {"status": "success", "shortenedUrl": final}

@app.get("/redirect")
async def redirect_page(request: Request, token: str = Query(None)):
    if not token: return HTMLResponse("<h1>Invalid Request</h1>", 400)
    data = decrypt_token(token)
    if not data: return HTMLResponse("<h1>Security Breach Detected</h1>", 403)
    
    link = await links_col.find_one({"random_id": data.get("i")})
    if not link: return HTMLResponse("<h1>Link Expired</h1>", 404)
    
    session = await create_secure_session(request, data.get("i"))
    
    return HTMLResponse(f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Security Shield</title>
        <meta name="viewport" content="width=device-width,initial-scale=1">
        <style>
            body {{ background: #020617; color: #f8fafc; font-family: system-ui; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }}
            .card {{ background: #0f172a; padding: 2.5rem; border-radius: 1rem; text-align: center; border: 1px solid #1e293b; max-width: 400px; width: 90%; }}
            .loader {{ border: 3px solid #1e293b; border-top: 3px solid #38bdf8; border-radius: 50%; width: 40px; height: 40px; animation: spin 1s linear infinite; margin: 20px auto; }}
            @keyframes spin {{ to {{ transform: rotate(360deg); }} }}
            .btn {{ display:none; background: #38bdf8; color: #020617; padding: 12px 24px; border-radius: 8px; text-decoration: none; font-weight: bold; margin-top: 20px; }}
            .status {{ color: #94a3b8; font-size: 0.9rem; }}
        </style>
    </head>
    <body>
        <div class="card">
            <div id="icon" style="font-size: 3rem; margin-bottom: 1rem;">🛡️</div>
            <h1 id="title">Verifying Access</h1>
            <p id="desc" class="status">Ensuring you came through our secure gateway...</p>
            <div id="loader" class="loader"></div>
            <a href="#" id="verifyBtn" class="btn">Click to Continue</a>
        </div>
        <script>
            const SEC = {{ sid: "{session['sid']}", csrf: "{session['csrf']}", token: "{token}" }};
            
            async function start() {{
                document.getElementById('desc').innerText = `Checking security headers...`;
                setTimeout(showBtn, 500); 
            }}

            function showBtn() {{
                document.getElementById('loader').style.display = 'none';
                const btn = document.getElementById('verifyBtn');
                btn.style.display = 'inline-block';
                btn.onclick = async (e) {{
                    e.preventDefault();
                    btn.innerText = "Validating...";
                    btn.style.pointerEvents = "none";
                    
                    const ans = eval("{session['expr']}");
                    const isBot = navigator.webdriver || !navigator.languages;

                    const res = await fetch('/verify', {{
                        method: 'POST',
                        headers: {{ 'Content-Type': 'application/json', 'X-CSRF': SEC.csrf }},
                        body: JSON.stringify({{ sid: SEC.sid, token: SEC.token, ans: ans.toString(), bot: isBot }})
                    }});
                    
                    const data = await res.json();
                    if(data.success) {{
                        window.location.href = data.url;
                    }} else {{
                        document.getElementById('title').innerText = "Access Denied";
                        document.getElementById('desc').innerText = data.message;
                        document.getElementById('icon').innerText = "⛔";
                        btn.style.display = 'none';
                    }}
                }};
            }}
            start();
        </script>
    </body>
    </html>
    """)

@app.post("/verify")
async def verify_request(request: Request):
    try:
        body = await request.json()
        sid, ans, token = body.get("sid"), body.get("ans"), body.get("token")
        is_bot = body.get("bot", False)
        csrf = request.headers.get("X-CSRF")
        
        # 1. Fetch session
        session = await sessions_col.find_one({"session_id": sid, "used": False})
        if not session: return JSONResponse({"success":False, "message": "Session Timeout"}, 403)
        
        # 2. CHECK BYPASS LOCK
        if session.get("is_bypassed"):
            return JSONResponse({
                "success": False, 
                "message": "Direct link access detected. You must go through the shortener page."
            }, 403)

        # 3. Fingerprint & Bot Logic
        if is_bot: return JSONResponse({"success":False, "message": "Automation detected."}, 403)
        
        curr_ip = request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or request.client.host
        if session["ip"] != curr_ip: return JSONResponse({"success":False, "message": "IP changed."}, 403)

        # 4. Token & CSRF Validation
        if not hmac.compare_digest(session["csrf"], csrf or ""): return JSONResponse({"success":False, "message": "CSRF Fail"}, 403)
        if not hmac.compare_digest(session["ans"], ans or ""): return JSONResponse({"success":False, "message": "Challenge Fail"}, 403)

        # 5. Mark used and release URL
        await sessions_col.update_one({"session_id": sid}, {"$set": {"used": True}})
        link = await links_col.find_one({"random_id": session["link_id"]})
        if not link: return JSONResponse({"success":False, "message": "Link Null"}, 404)
        
        await links_col.update_one({"random_id": session["link_id"]}, {"$inc": {"clicks": 1}})
        return {"success": True, "url": link["original_url"]}
        
    except: return JSONResponse({"success":False, "message": "System Error"}, 500)

@app.get("/stats")
async def stats(api: str = Query(None)):
    if api != ADMIN_API_KEY: return JSONResponse({"error":1}, 403)
    links = await links_col.count_documents({})
    sess = await sessions_col.count_documents({})
    return {"total_links": links, "active_sessions": sess}

@app.on_event("startup")
async def on_start():
    await init_db()
    # Aggressive startup cleanup
    await sessions_col.delete_many({})
    print("ULTRA SECURITY ONLINE")
