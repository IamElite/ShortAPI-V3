# ===============================================
# Shortener API - ULTRA REINFORCED SECURITY v7.0
# Optimized Speed + Advanced Anti-Proxy/Bot Protection
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
SECRET_KEY = os.getenv("SECRET_KEY", "CyberSafe2025!@#")
CHALLENGE_SECRET = os.getenv("CHALLENGE_SECRET", "HyperChallenge2025!@#")

# Timing & Security
LINK_EXPIRY_SECONDS = 30 * 24 * 60 * 60
SESSION_EXPIRY = 300 # 5 minutes is enough

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
        await sessions_col.create_index("session_id", unique=True)
    except: pass

app = FastAPI(on_startup=[init_db])

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# ================= SECURITY HELPERS =================

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

# ================= ADVANCED PROTECTION =================

def get_client_ip(request: Request) -> str:
    xff = request.headers.get("X-Forwarded-For")
    if xff: return xff.split(",")[0].strip()
    return request.headers.get("X-Real-IP") or (request.client.host if request.client else "unknown")

def is_suspicious_traffic(request: Request) -> bool:
    """Detects proxies, Tor, and automation headers"""
    bad_headers = [
        "x-proxy-id", "x-forwarded-proto", "via", "forwarded", 
        "x-authenticated-proxy", "x-proxy-user"
    ]
    for h in bad_headers:
        if request.headers.get(h): return True
    
    # Check for empty or generic UA common in simple proxy bots
    ua = request.headers.get("User-Agent", "").lower()
    if not ua or "curl" in ua or "python" in ua or "wget" in ua: return True
    
    return False

def check_referer_is_valid(referer: str) -> bool:
    if not referer: return False
    domain = urlparse(referer).netloc.lower()
    return SHORTENER_DOMAIN.lower() in domain

async def create_secure_session(request: Request, link_id: str) -> dict:
    session_id = secrets.token_hex(32)
    referer = request.headers.get("referer", "")
    ip = get_client_ip(request)
    ua = request.headers.get("User-Agent", "")[:250]
    
    # Strict bypass detection
    is_bypassed = not check_referer_is_valid(referer)
    is_suspicious = is_suspicious_traffic(request)
    
    # JS Challenge
    s1, s2 = secrets.randbelow(50)+1, secrets.randbelow(50)+1
    salt_val = secrets.randbelow(1000000)
    # Challenge logic: (s1 * s2) + salt_val
    expr = f"({s1} * {s2}) + {salt_val}"
    ans = str((s1 * s2) + salt_val)
    
    csrf = secrets.token_urlsafe(32)
    
    await sessions_col.insert_one({
        "session_id": session_id,
        "link_id": link_id,
        "ip": ip,
        "ua": ua,
        "csrf": csrf,
        "ans": ans,
        "is_bypassed": is_bypassed or is_suspicious, # BLOCK IF SUSPICIOUS
        "created_at": time.time(),
        "used": False
    })
    return {"sid": session_id, "csrf": csrf, "expr": expr}

# ================= ROUTES =================

@app.get("/api")
async def create_link(request: Request, api: str = Query(None), url: str = Query(None)):
    if api != ADMIN_API_KEY: return JSONResponse({"status":"error"}, 403)
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
    if not token: return HTMLResponse("<h1>Invalid</h1>", 400)
    data = decrypt_token(token)
    if not data: return HTMLResponse("<h1>Secure Link Only</h1>", 403)
    
    link = await links_col.find_one({"random_id": data.get("i")})
    if not link: return HTMLResponse("<h1>Expired</h1>", 404)
    
    # SESSION CREATION (Optimized)
    session = await create_secure_session(request, data.get("i"))
    
    # HTML Response - OPTIMIZED FOR SPEED
    return HTMLResponse(f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Verifying...</title>
        <style>
            body {{ background: #0b0e14; color: #fff; font-family: -apple-system, sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }}
            .card {{ background: #151921; border: 1px solid #242933; padding: 2rem; border-radius: 12px; text-align: center; width: 320px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }}
            .spin {{ width: 32px; height: 32px; border: 3px solid #3d4451; border-top-color: #3b82f6; border-radius: 50%; animation: s 0.6s linear infinite; margin: 1rem auto; }}
            @keyframes s {{ to {{ transform: rotate(360deg); }} }}
            .btn {{ display: none; background: #3b82f6; color: white; border: none; padding: 10px 20px; border-radius: 6px; cursor: pointer; font-weight: 600; width: 100%; font-size: 15px; margin-top: 15px; }}
            .btn:hover {{ background: #2563eb; }}
            .status {{ color: #94a3b8; font-size: 13px; }}
            #hp {{ position: absolute; opacity: 0; height: 0; width: 0; z-index: -1; }}
        </style>
    </head>
    <body>
        <div class="card">
            <h2 id="t">Verifying Gateway</h2>
            <div id="l" class="spin"></div>
            <p id="s" class="status">Initial security check...</p>
            <input type="text" id="hp" name="hp_field" tabindex="-1" autocomplete="off">
            <button id="b" class="btn" onclick="v()">Verify & Continue</button>
        </div>
        <script>
            const S = {{ sid: "{session['sid']}", csrf: "{session['csrf']}", token: "{token}" }};
            
            // Background pre-check and bot detection
            (function() {{
                const detect = () => {{
                    if (navigator.webdriver) return true;
                    if (!navigator.languages || navigator.languages.length === 0) return true;
                    if (window.outerWidth === 0 && window.outerHeight === 0) return true;
                    return false;
                }};
                window._isBot = detect();
            }})();

            // FAST SHOW (Remove artificial delay)
            setTimeout(() => {{
                document.getElementById('l').style.display = 'none';
                document.getElementById('b').style.display = 'block';
                document.getElementById('s').innerText = "Security check completed.";
            }}, 300);

            async function v() {{
                const btn = document.getElementById('b');
                const t = document.getElementById('t');
                const s = document.getElementById('s');
                const hp = document.getElementById('hp').value;

                btn.disabled = true;
                btn.innerText = "Processing...";
                
                // Solve JS Challenge
                const ans = eval("{session['expr']}");
                
                try {{
                    const r = await fetch('/verify', {{
                        method: 'POST',
                        headers: {{ 'Content-Type': 'application/json', 'X-CSRF': S.csrf }},
                        body: JSON.stringify({{ 
                            sid: S.sid, 
                            ans: ans.toString(), 
                            bot: window._isBot,
                            hp: hp // Honeypot Field
                        }})
                    }});
                    
                    const d = await r.json();
                    if(d.success) {{
                        t.innerText = "Success!";
                        s.innerText = "Redirecting now...";
                        window.location.href = d.url;
                    }} else {{
                        t.innerText = "Access Denied";
                        s.innerText = d.message;
                        s.style.color = "#ef4444";
                        btn.style.display = 'none';
                    }}
                }} catch(e) {{
                    s.innerText = "Network Error. Please refresh.";
                    btn.disabled = false;
                    btn.innerText = "Try Again";
                }}
            }}
        </script>
    </body>
    </html>
    """)

@app.post("/verify")
async def verify_request(request: Request):
    try:
        body = await request.json()
        sid, ans = body.get("sid"), body.get("ans")
        is_bot_client = body.get("bot", False)
        hp_val = body.get("hp", "")
        csrf = request.headers.get("X-CSRF")
        
        # 1. Fetch & Check Session
        session = await sessions_col.find_one({"session_id": sid, "used": False})
        if not session: return JSONResponse({"success":False, "message": "Session Inactive"}, 403)
        
        # 2. ULTRA BYPASS DETECTION
        if session.get("is_bypassed"):
            return JSONResponse({"success":False, "message": "Direct/Suspicious access blocked."}, 403)
        
        # 3. Honeypot check (Bots fill hidden fields)
        if hp_val: return JSONResponse({"success":False, "message": "Automation detected (HP)."}, 403)

        # 4. Fingerprint checks
        if is_bot_client: return JSONResponse({"success":False, "message": "Bot profile detected."}, 403)
        
        # IP consistency check
        if session["ip"] != get_client_ip(request):
            return JSONResponse({"success":False, "message": "Proxy rotation detected."}, 403)

        # 5. Crypto/CSRF checks
        if not hmac.compare_digest(session["csrf"], csrf or ""): return JSONResponse({"success":False, "message": "CSRF Error"}, 403)
        if not hmac.compare_digest(session["ans"], ans or ""): return JSONResponse({"success":False, "message": "Logic Error"}, 403)

        # 6. Mark used and release URL
        await sessions_col.update_one({"session_id": sid}, {"$set": {"used": True}})
        link = await links_col.find_one({"random_id": session["link_id"]})
        if not link: return JSONResponse({"success":False, "message": "Link Expired"}, 404)
        
        await links_col.update_one({"random_id": session["link_id"]}, {"$inc": {"clicks": 1}})
        return {"success": True, "url": link["original_url"]}
        
    except: return JSONResponse({"success":False, "message": "Server Error"}, 500)

@app.get("/stats")
async def stats(api: str = Query(None)):
    if api != ADMIN_API_KEY: return JSONResponse({"error":1}, 403)
    c_links = await links_col.count_documents({})
    c_sess = await sessions_col.count_documents({"used": False})
    return {"total_links": c_links, "active_sessions": c_sess}

@app.on_event("startup")
async def on_start():
    await init_db()
    # Cleanup on restart
    await sessions_col.delete_many({})
    print("ULTRA SPEED & SECURITY ONLINE")
