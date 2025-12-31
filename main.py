# ===============================================
# Shortener API - IRON GATE v11.0 (BOT-TRAP)
# Blacklists tokens exposed by bypass bots
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

SECRET_KEY = os.getenv("SECRET_KEY", "BotTrap2025!@#")

# Timing
LINK_EXPIRY_SECONDS = 3 * 24 * 60 * 60 
SESSION_EXPIRY = 600

# ================= DATABASE SETUP =================
client = AsyncIOMotorClient(MONGO_URI)
db = client["shortener_db"]
links_col = db["links"]
sessions_col = db["sessions"]
abuse_col = db["token_abuse"] # Blacklisted tokens go here

async def init_db():
    try:
        await links_col.create_index("created_at", expireAfterSeconds=LINK_EXPIRY_SECONDS)
        await sessions_col.create_index("created_at", expireAfterSeconds=SESSION_EXPIRY)
        await abuse_col.create_index("created_at", expireAfterSeconds=3600) # Only block for 1hr
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
        dec = bytes([enc[i] ^ key[i % len(key)] for i in range(len(enc))])
        return json.loads(dec.decode())
    except: return None

def is_bot(ua: str) -> bool:
    """Detects bots and bypass tool signatures"""
    if not ua: return True
    ua = ua.lower()
    bot_keywords = ["python", "curl", "wget", "telegram", "bot", "spider", "crawl", "cloud", "headless", "aiohttp", "httpx", "go-http"]
    return any(bk in ua for bk in bot_keywords)

# ================= ROUTES =================

@app.get("/api")
async def create_link(request: Request, api: str = Query(None), url: str = Query(None)):
    if api != ADMIN_API_KEY: return JSONResponse({"status":"error"}, 403)
    rid = secrets.token_urlsafe(8)
    token = encrypt_token({"i": rid, "t": int(time.time()), "s": secrets.token_hex(4)})
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
async def gate_handler(request: Request, token: str = Query(None)):
    if not token: return HTMLResponse("Denied", 403)
    data = decrypt_token(token)
    if not data: return HTMLResponse("Access Denied", 403)
    
    ua = request.headers.get("User-Agent", "")
    ip = get_client_ip(request)
    token_hash = hashlib.md5(token.encode()).hexdigest()

    # 1. BOT TRAP: If a bot hits this, blacklist the token FOREVER for everyone
    if is_bot(ua):
        await abuse_col.update_one(
            {"token_hash": token_hash},
            {"$set": {"reason": f"Exposed by bot: {ua[:50]}", "created_at": time.time()}},
            upsert=True
        )
        return HTMLResponse("<h1>Bot Blocked</h1>", status_code=403)

    # 2. CHECK BLACKLIST: Did a bot touch this token before the user?
    abuse = await abuse_col.find_one({"token_hash": token_hash})
    if abuse:
        return HTMLResponse(f"""
        <body style="background:#0a0a0a;color:#ff4444;font-family:sans-serif;text-align:center;padding:50px;">
            <h1>⛔ Link Compromised</h1>
            <p style="color:#666;">This link has been exposed by an unauthorized bypass bot and is now blocked.</p>
            <p style="color:#444;font-size:0.8rem;">Please use the original short link from the source.</p>
        </body>
        """, status_code=403)

    # 3. Create Session
    session_id = secrets.token_hex(32)
    csrf = secrets.token_urlsafe(16)
    n1, n2 = secrets.randbelow(50)+1, secrets.randbelow(50)+1
    ans = str(n1 + n2)

    await sessions_col.insert_one({
        "session_id": session_id,
        "link_id": data["i"],
        "ip": ip,
        "csrf": csrf,
        "ans": ans,
        "created_at": time.time(),
        "used": False
    })

    return HTMLResponse(f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8"><title>Finalizing...</title>
        <meta name="viewport" content="width=device-width,initial-scale=1">
        <style>
            body {{ background:#050505; color:white; font-family:sans-serif; display:flex; align-items:center; justify-content:center; height:100vh; margin:0; }}
            .c {{ background:#111; border:1px solid #222; padding:2rem; border-radius:12px; text-align:center; width:280px; }}
            .l {{ border:3px solid #222; border-top:3px solid #3b82f6; border-radius:50%; width:30px; height:30px; animation:spin 0.7s linear infinite; margin:1rem auto; }}
            @keyframes spin {{ to {{ transform:rotate(360deg); }} }}
            .btn {{ display:none; background:#3b82f6; color:white; border:0; padding:12px; border-radius:6px; font-weight:700; cursor:pointer; width:100%; }}
        </style>
    </head>
    <body>
        <div class="c">
            <h2 style="margin:0 0 1rem 0;">Ready</h2>
            <div id="l" class="l"></div>
            <button id="b" class="btn" onclick="v()">Verify & Get Link</button>
        </div>
        <script>
            setTimeout(() => {{ 
                document.getElementById('l').style.display='none';
                document.getElementById('b').style.display='block';
            }}, 500);

            async function v() {{
                const res = await fetch('/verify', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json', 'X-CSRF': "{csrf}" }},
                    body: JSON.stringify({{ sid: "{session_id}", ans: ({n1}+{n2}).toString() }})
                }});
                const d = await res.json();
                if(d.success) window.location.href = d.url; else alert(d.message);
            }}
        </script>
    </body>
    </html>
    """)

@app.post("/verify")
async def verify(request: Request):
    try:
        body = await request.json()
        sid, ans = body.get("sid"), body.get("ans")
        csrf = request.headers.get("X-CSRF")
        
        session = await sessions_col.find_one({"session_id": sid, "used": False})
        if not session: return JSONResponse({"success":False, "message": "Session Expired"}, 403)
        
        # Security Consistency
        if session["ip"] != get_client_ip(request): return JSONResponse({"success":False, "message": "IP Mismatch"}, 403)
        if not hmac.compare_digest(session["csrf"], csrf or ""): return JSONResponse({"success":False, "message": "Security Error"}, 403)
        if not hmac.compare_digest(session["ans"], ans or ""): return JSONResponse({"success":False, "message": "Logic Error"}, 403)

        # OK
        await sessions_col.update_one({"session_id": sid}, {"$set": {"used": True}})
        link = await links_col.find_one({"random_id": session["link_id"]})
        
        await links_col.update_one({"random_id": session["link_id"]}, {"$inc": {"clicks": 1}})
        return {"success": True, "url": link["original_url"]}
    except: return JSONResponse({"success":False, "message": "System Error"}, 500)

@app.on_event("startup")
async def start():
    await init_db()
    await sessions_col.delete_many({})
    print("IRON GATE v11.0 (BOT-TRAP) ONLINE")
