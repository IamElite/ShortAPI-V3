# ===============================================
# Shortener API - IRON GATE v10.0 (REFERER-LOCKED)
# Blocks Bypassed Links Shared in Telegram/Bots
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
from fastapi import FastAPI, Request, Query, Response, Cookie
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient

# ================= CONFIGURATION =================
MONGO_URI = os.getenv("MONGO_URI", "mongodb+srv://hnyx:wywyw2@cluster0.9dxlslv.mongodb.net/?retryWrites=true&w=majority")
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "MY_SECRET_PASS_123")
SHORTENER_DOMAIN = os.getenv("SHORTENER_DOMAIN", "nanolinks.in")
SHORTENER_API = os.getenv("SHORTENER_API", "ae0271c2c57105db2fa209f5b0f20c1a965343f6")

SECRET_KEY = os.getenv("SECRET_KEY", "RefererLock2025!@#")

# Timing & Cleanup
LINK_EXPIRY_SECONDS = 3 * 24 * 60 * 60 # 3 Days
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

# ================= SECURITY HELPERS =================

def get_client_ip(request: Request) -> str:
    xff = request.headers.get("X-Forwarded-For")
    if xff: return xff.split(",")[0].strip()
    return request.headers.get("X-Real-IP") or (request.client.host if request.client else "unknown")

def encrypt_token(data: dict) -> str:
    key = hashlib.sha256(SECRET_KEY.encode()).digest()
    msg = json.dumps(data, separators=(',', ':')).encode()
    enc = bytes([msg[i] ^ key[i % len(key)] for i in range(len(msg))])
    b64 = base64.urlsafe_b64encode(enc).decode().rstrip('=')
    sig = hmac.new(key, b64.encode(), hashlib.sha256).hexdigest()[:12]
    return f"{b64}.{sig}"

def decrypt_token(token: str) -> dict:
    try:
        b64, sig = token.rsplit('.', 1)
        key = hashlib.sha256(SECRET_KEY.encode()).digest()
        if not hmac.compare_digest(sig, hmac.new(key, b64.encode(), hashlib.sha256).hexdigest()[:12]): return None
        pad = 4 - len(b64) % 4
        if pad != 4: b64 += '=' * pad
        enc = base64.urlsafe_b64decode(b64)
        dec = bytes([enc[i] ^ key[i % len(enc)] for i in range(len(enc))])
        return json.loads(dec.decode())
    except: return None

def is_valid_referer(referer: str) -> bool:
    """STRICT: Check if coming from shortener domain"""
    if not referer: return False
    domain = urlparse(referer).netloc.lower()
    return SHORTENER_DOMAIN.lower() in domain

# ================= ROUTES =================

@app.get("/api")
async def create_link(request: Request, api: str = Query(None), url: str = Query(None)):
    if api != ADMIN_API_KEY: return JSONResponse({"status":"error"}, 403)
    rid = secrets.token_urlsafe(8)
    # Token is encrypted with short expiry data
    token = encrypt_token({"i": rid, "t": int(time.time()), "r": secrets.token_hex(4)})
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
async def gatekeeper(request: Request, token: str = Query(None)):
    if not token: return HTMLResponse("Blocked", 403)
    data = decrypt_token(token)
    if not data: return HTMLResponse("Access Denied", 403)
    
    # 1. STRICT REFERER CHECK (This stops bypassed links from Telegram)
    referer = request.headers.get("referer", "")
    if not is_valid_referer(referer):
        return HTMLResponse(f"""
        <body style="background:#0a0a0a;color:#ff4444;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;text-align:center;">
            <div>
                <h1 style="font-size:3rem;">⛔ Access Denied</h1>
                <p style="color:#666;">Bypass detected. Direct link access is strictly prohibited.</p>
                <p style="color:#444;font-size:0.8rem;">You must go through <b>{SHORTENER_DOMAIN}</b> ads to get the original link.</p>
                <p style="color:#333;margin-top:2rem;"><i>Reason: Referer Missing/Invalid</i></p>
            </div>
        </body>
        """, status_code=403)

    # 2. BOT UA CHECK
    ua = request.headers.get("User-Agent", "").lower()
    if any(b in ua for b in ["bot", "python", "curl", "wget", "telegram", "cloud"]):
        return HTMLResponse("<h1>Bot Blocked</h1>", status_code=403)

    # 3. Create Session
    session_id = secrets.token_hex(32)
    csrf = secrets.token_urlsafe(16)
    n1, n2 = secrets.randbelow(50)+1, secrets.randbelow(50)+1
    ans = str(n1 * n2)

    await sessions_col.insert_one({
        "session_id": session_id,
        "link_id": data["i"],
        "ip": get_client_ip(request),
        "ans": ans,
        "csrf": csrf,
        "created_at": time.time(),
        "used": False
    })

    resp = HTMLResponse(f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8"><title>Verifying...</title>
        <meta name="viewport" content="width=device-width,initial-scale=1">
        <style>
            body {{ background:#050505; color:white; font-family:sans-serif; display:flex; align-items:center; justify-content:center; height:100vh; margin:0; }}
            .box {{ background:#111; border:1px solid #222; padding:2.5rem; border-radius:15px; text-align:center; width:280px; box-shadow:0 15px 35px rgba(0,0,0,0.5); }}
            .loader {{ border:3px solid #222; border-top:3px solid #007bff; border-radius:50%; width:35px; height:35px; animation:spin 0.8s linear infinite; margin:1rem auto; }}
            @keyframes spin {{ to {{ transform:rotate(360deg); }} }}
            .btn {{ display:none; background:#007bff; color:white; border:0; padding:12px; border-radius:8px; font-weight:700; cursor:pointer; width:100%; font-size:1rem; }}
        </style>
    </head>
    <body>
        <div class="box">
            <h2 style="margin:0 0 1rem 0;">Security Shield</h2>
            <div id="l" class="loader"></div>
            <p id="s" style="color:#666;font-size:0.8rem;">Checking headers...</p>
            <button id="b" class="btn" onclick="v()">Get My Link</button>
        </div>
        <script>
            setTimeout(() => {{ 
                document.getElementById('l').style.display='none';
                document.getElementById('b').style.display='block';
                document.getElementById('s').innerText='Security check complete.';
            }}, 500);

            async function v() {{
                const btn = document.getElementById('b');
                btn.disabled = true; btn.innerText = "Redirecting...";
                const res = await fetch('/verify', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json', 'X-CSRF': "{csrf}" }},
                    body: JSON.stringify({{ sid: "{session_id}", ans: ({n1}*{n2}).toString() }})
                }});
                const d = await res.json();
                if(d.success) window.location.href = d.url;
                else {{ alert(d.message); location.reload(); }}
            }}
        </script>
    </body>
    </html>
    """)
    resp.set_cookie(key="gate_pass", value=session_id, httponly=True)
    return resp

@app.post("/verify")
async def verify(request: Request, gate_pass: str = Cookie(None)):
    try:
        body = await request.json()
        sid, ans = body.get("sid"), body.get("ans")
        csrf = request.headers.get("X-CSRF")
        
        if not gate_pass or gate_pass != sid: return JSONResponse({"success":False, "message": "Verification Expired"}, 403)
        
        session = await sessions_col.find_one({"session_id": sid, "used": False})
        if not session: return JSONResponse({"success":False, "message": "Session Not Found"}, 403)
        
        # IP Lock
        if session["ip"] != get_client_ip(request): return JSONResponse({"success":False, "message": "Network Changed"}, 403)
        
        # Challenge Checks
        if not hmac.compare_digest(session["csrf"], csrf or ""): return JSONResponse({"success":False, "message": "Security Error"}, 403)
        if not hmac.compare_digest(session["ans"], ans or ""): return JSONResponse({"success":False, "message": "Challenge Error"}, 403)

        # Success Handler
        await sessions_col.update_one({"session_id": sid}, {"$set": {"used": True}})
        link = await links_col.find_one({"random_id": session["link_id"]})
        
        await links_col.update_one({"random_id": session["link_id"]}, {"$inc": {"clicks": 1}})
        return {"success": True, "url": link["original_url"]}
    except: return JSONResponse({"success":False, "message": "System Error"}, 500)

@app.get("/stats")
async def stats(api: str = Query(None)):
    if api != ADMIN_API_KEY: return JSONResponse({"error":1}, 403)
    c_links = await links_col.count_documents({})
    c_sess = await sessions_col.count_documents({"used": False})
    return {"total_links": c_links, "active_sessions": c_sess}

@app.on_event("startup")
async def startup():
    await init_db()
    # Always clear sessions on startup to prevent bloat
    await sessions_col.delete_many({})
    print("IRON GATE v10.0 (STRICT REFERER) ONLINE")
