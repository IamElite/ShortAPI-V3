import os, time, secrets, json, base64, hashlib, hmac, urllib.request, asyncio
from urllib.parse import quote, urlparse
from fastapi import FastAPI, Request, Query, Cookie
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient

MONGO_URI = os.getenv("MONGO_URI", "mongodb+srv://hnyx:wywyw2@cluster0.9dxlslv.mongodb.net/?retryWrites=true&w=majority")
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "MY_SECRET_PASS_123")
SHORTENER_DOMAIN = os.getenv("SHORTENER_DOMAIN", "nanolinks.in")
SHORTENER_API = os.getenv("SHORTENER_API", "ae0271c2c57105db2fa209f5b0f20c1a965343f6")
SECRET_KEY = os.getenv("SECRET_KEY", "DebugMode2025!@#")
LINK_EXPIRY = 3 * 24 * 60 * 60
SESSION_EXPIRY = 300

client = AsyncIOMotorClient(MONGO_URI)
db = client["shortener_db"]
links_col = db["links"]
sessions_col = db["sessions"]
logs_col = db["access_logs"]

async def init_db():
    try:
        await links_col.create_index("created_at", expireAfterSeconds=LINK_EXPIRY)
        await sessions_col.create_index("created_at", expireAfterSeconds=SESSION_EXPIRY)
        await logs_col.create_index("created_at", expireAfterSeconds=3600)
    except: pass

app = FastAPI(on_startup=[init_db])
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

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

def get_ip(req: Request) -> str:
    xff = req.headers.get("X-Forwarded-For")
    return xff.split(",")[0].strip() if xff else (req.client.host if req.client else "?")

async def log_request(req: Request, event: str, details: dict = {}):
    log_entry = {
        "event": event,
        "ip": get_ip(req),
        "referer": req.headers.get("referer", "EMPTY"),
        "user_agent": req.headers.get("user-agent", "EMPTY")[:200],
        "all_headers": dict(req.headers),
        "created_at": time.time(),
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        **details
    }
    await logs_col.insert_one(log_entry)
    print(f"[LOG] {event} | IP: {log_entry['ip']} | Referer: {log_entry['referer'][:50]}")

@app.get("/api")
async def create_link(request: Request, api: str = Query(None), url: str = Query(None)):
    if api != ADMIN_API_KEY: return JSONResponse({"error": "auth"}, 403)
    rid = secrets.token_urlsafe(8)
    token = encrypt_token({"i": rid, "t": int(time.time())})
    await links_col.update_one({"random_id": rid}, {"$set": {"original_url": url, "created_at": time.time(), "clicks": 0}}, upsert=True)
    
    base = str(request.base_url).rstrip("/").replace("http://", "https://") if "localhost" not in str(request.base_url) else str(request.base_url).rstrip("/")
    red_url = f"{base}/redirect?token={token}"
    
    final = red_url
    if SHORTENER_API:
        try:
            with urllib.request.urlopen(f"https://{SHORTENER_DOMAIN}/api?api={SHORTENER_API}&url={quote(red_url)}", timeout=5) as r:
                d = json.loads(r.read().decode())
                if d.get("status") == "success": final = d.get("shortenedUrl")
        except: pass
    return {"status": "success", "shortenedUrl": final}

@app.get("/redirect")
async def redirect_page(request: Request, token: str = Query(None)):
    if not token: return HTMLResponse("Blocked", 403)
    
    await log_request(request, "REDIRECT_PAGE_HIT", {"token": token[:20]})
    data = decrypt_token(token)
    if not data: return HTMLResponse("Invalid", 403)
    
    link = await links_col.find_one({"random_id": data.get("i")})
    if not link: return HTMLResponse("Expired", 404)

    referer = request.headers.get("referer", "")
    has_valid_referer = len(referer.strip()) > 0
    
    await log_request(request, "REFERER_CHECK", {
        "referer_value": referer,
        "shortener_domain": SHORTENER_DOMAIN,
        "is_valid": has_valid_referer
    })
    
    try:
        session_id = secrets.token_hex(24)
        csrf = secrets.token_urlsafe(16)
        n1, n2 = secrets.randbelow(50)+1, secrets.randbelow(50)+1
        
        await sessions_col.insert_one({
            "session_id": session_id,
            "link_id": data["i"],
            "ip": get_ip(request),
            "csrf": csrf,
            "ans": str(n1*n2),
            "valid_referer": has_valid_referer,
            "created_at": time.time(),
            "used": False
        })
    except Exception as e:
        return HTMLResponse(f"Error: {str(e)}", 500)

    return HTMLResponse(f"""
<!DOCTYPE html>
<html>
<head>
    <title>Verification</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <style>
        body{{background:#0a0a0a;color:#fff;font-family:system-ui;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}}
        .box{{background:#111;border:1px solid #222;padding:2rem;border-radius:12px;text-align:center;width:300px}}
        .btn{{background:#2563eb;color:#fff;border:0;padding:12px 24px;border-radius:8px;font-weight:700;cursor:pointer;width:100%;font-size:1rem;margin-top:1rem}}
        .btn:disabled{{background:#333;cursor:not-allowed}}
        #msg{{color:#666;font-size:0.85rem;margin-top:1rem}}
    </style>
</head>
<body>
    <div class="box">
        <h2>🔐 Security Check</h2>
        <p style="color:#888;font-size:0.9rem">Complete verification to continue</p>
        <button id="btn" class="btn" disabled>Loading...</button>
        <p id="msg">Initializing...</p>
    </div>
    <script>
        const S = {{ sid: "{session_id}", csrf: "{csrf}", n1: {n1}, n2: {n2} }};

        setTimeout(() => {{
            document.cookie = "v_init=" + S.sid + ";path=/;max-age=300;SameSite=Lax";
            document.getElementById('btn').disabled = false;
            document.getElementById('btn').innerText = "Get Link";
            document.getElementById('msg').innerText = "Click to proceed";
        }}, 1000);

        document.getElementById('btn').onclick = async () => {{
            const btn = document.getElementById('btn');
            btn.disabled = true;
            btn.innerText = "Verifying...";
            
            const ans = S.n1 * S.n2;
            try {{
                const res = await fetch('/verify', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json', 'X-CSRF': S.csrf }},
                    body: JSON.stringify({{ sid: S.sid, ans: ans.toString() }})
                }});
                const d = await res.json();
                if(d.success) {{
                    window.location.href = d.url;
                }} else {{
                    document.getElementById('msg').innerText = "❌ " + d.message;
                    btn.innerText = "Failed";
                }}
            }} catch(e) {{
                document.getElementById('msg').innerText = "Network error";
            }}
        }};
    </script>
</body>
</html>
    """)

@app.post("/verify")
async def verify(request: Request, v_init: str = Cookie(None)):
    try:
        body = await request.json()
        sid, ans = body.get("sid"), body.get("ans")
        csrf = request.headers.get("X-CSRF")
        
        await log_request(request, "VERIFY_ATTEMPT", {"sid": sid[:20] if sid else "NONE", "cookie_present": bool(v_init)})
        
        if not v_init or v_init != sid:
            await log_request(request, "VERIFY_FAIL", {"reason": "Cookie missing or mismatch"})
            return JSONResponse({"success": False, "message": "Browser verification failed."}, 403)
        
        session = await sessions_col.find_one({"session_id": sid, "used": False})
        if not session:
            await log_request(request, "VERIFY_FAIL", {"reason": "Session not found"})
            return JSONResponse({"success": False, "message": "Session expired"}, 403)
        
        if not session.get("valid_referer"):
            await log_request(request, "VERIFY_FAIL", {"reason": "Invalid referer at session creation"})
            return JSONResponse({"success": False, "message": "Direct access blocked. Use shortener link."}, 403)
        
        if session["ip"] != get_ip(request):
            await log_request(request, "VERIFY_FAIL", {"reason": "IP mismatch"})
            return JSONResponse({"success": False, "message": "Network changed"}, 403)
        
        if not hmac.compare_digest(session["csrf"], csrf or ""):
            return JSONResponse({"success": False, "message": "Security error"}, 403)
        if not hmac.compare_digest(session["ans"], ans or ""):
            return JSONResponse({"success": False, "message": "Verification failed"}, 403)
        
        await sessions_col.update_one({"session_id": sid}, {"$set": {"used": True}})
        link = await links_col.find_one({"random_id": session["link_id"]})
        await links_col.update_one({"random_id": session["link_id"]}, {"$inc": {"clicks": 1}})
        
        await log_request(request, "VERIFY_SUCCESS", {"link_id": session["link_id"]})
        
        return {"success": True, "url": link["original_url"]}
        
    except Exception as e:
        await log_request(request, "VERIFY_ERROR", {"error": str(e)})
        return JSONResponse({"success": False, "message": "Error"}, 500)

@app.get("/logs")
async def view_logs(api: str = Query(None), limit: int = Query(50)):
    if api != ADMIN_API_KEY: return JSONResponse({"error": "auth"}, 403)
    logs = await logs_col.find().sort("created_at", -1).limit(limit).to_list(limit)
    for log in logs:
        log["_id"] = str(log["_id"])
        if "all_headers" in log: del log["all_headers"]
    return {"total": len(logs), "logs": logs}

@app.get("/cleanup")
async def cleanup_db(api: str = Query(None)):
    if api != ADMIN_API_KEY: return JSONResponse({"error": "auth"}, 403)
    logs_deleted = await logs_col.delete_many({})
    sessions_deleted = await sessions_col.delete_many({})
    return {"status": "success", "logs_deleted": logs_deleted.deleted_count, "sessions_deleted": sessions_deleted.deleted_count}

async def auto_cleanup_task():
    while True:
        await asyncio.sleep(600)
        try:
            cutoff = time.time() - 1800
            await logs_col.delete_many({"created_at": {"$lt": cutoff}})
            await sessions_col.delete_many({"used": True})
            print(f"[AUTO-CLEANUP] Ran at {time.strftime('%H:%M:%S')}")
        except: pass

@app.on_event("startup")
async def start():
    await init_db()
    await sessions_col.delete_many({})
    await logs_col.delete_many({})
    asyncio.create_task(auto_cleanup_task())
    print("SERVER ONLINE")
