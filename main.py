import random, os, time, secrets, json, base64, hashlib, hmac, urllib.request, asyncio
from urllib.parse import quote, urlparse
from fastapi import FastAPI, Request, Query, Cookie
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient

MONGO_URI_1 = os.getenv("MONGO_URI_1", "mongodb+srv://hnyx:wywyw2@cluster0.9dxlslv.mongodb.net/?retryWrites=true&w=majority")
MONGO_URI_2 = os.getenv("MONGO_URI_2", "mongodb+srv://public:abishnoimf@cluster0.rqk6ihd.mongodb.net/?retryWrites=true&w=majority")
MONGO_URI_3 = os.getenv("MONGO_URI_3", "mongodb+srv://ravi:ravi12345@cluster0.hndinhj.mongodb.net/?retryWrites=true&w=majority")

ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "MY_SECRET_PASS_123")

SHORT_BASE_1 = os.getenv("SHORT_BASE_1", "nanolinks.in")
SHORT_API_1 = os.getenv("SHORT_API_1", "ae0271c2c57105db2fa209f5b0f20c1a965343f6")

SHORT_BASE_2 = os.getenv("SHORT_BASE_2", "")
SHORT_API_2 = os.getenv("SHORT_API_2", "")

SHORT_BASE_3 = os.getenv("SHORT_BASE_3", "")
SHORT_API_3 = os.getenv("SHORT_API_3", "")

SHORT_BASE_4 = os.getenv("SHORT_BASE_4", "")
SHORT_API_4 = os.getenv("SHORT_API_4", "")

SHORT_BASE_5 = os.getenv("SHORT_BASE_5", "")
SHORT_API_5 = os.getenv("SHORT_API_5", "")

def get_random_shortener():
    providers = [(SHORT_BASE_1, SHORT_API_1), (SHORT_BASE_2, SHORT_API_2), (SHORT_BASE_3, SHORT_API_3), (SHORT_BASE_4, SHORT_API_4), (SHORT_BASE_5, SHORT_API_5)]
    active = [(d, a) for d, a in providers if d and a]
    return random.choice(active) if active else (None, None)

TOKEN_EXPIRY_SECONDS = 3600
LINK_EXPIRY = 3 * 24 * 60 * 60
SESSION_EXPIRY = 300

DB = {}

def init_mongo():
    uris = [u for u in [MONGO_URI_1, MONGO_URI_2, MONGO_URI_3] if u]
    for uri in uris:
        try:
            DB['client'] = AsyncIOMotorClient(uri, serverSelectionTimeoutMS=5000)
            DB['db'] = DB['client']["shortener_db"]
            DB['links'] = DB['db']["links"]
            DB['sessions'] = DB['db']["sessions"]
            DB['logs'] = DB['db']["access_logs"]
            DB['config'] = DB['db']["config"]
            print(f"[MONGO] Connected: {uri[:40]}...")
            return True
        except:
            continue
    return False

init_mongo()

SECRET_KEY = None

async def get_or_create_secret_key():
    global SECRET_KEY
    config = await DB['config'].find_one({"key": "secret_key"})
    if config:
        SECRET_KEY = config["value"]
    else:
        SECRET_KEY = secrets.token_hex(32)
        await DB['config'].insert_one({"key": "secret_key", "value": SECRET_KEY, "created_at": time.time()})
        await DB['sessions'].delete_many({})
        await DB['links'].delete_many({})
        await DB['logs'].delete_many({})
        print("[NEW KEY] Generated new SECRET_KEY, cleared old data")
    return SECRET_KEY

async def init_db():
    try:
        await DB['links'].create_index("created_at", expireAfterSeconds=LINK_EXPIRY)
        await DB['sessions'].create_index("created_at", expireAfterSeconds=SESSION_EXPIRY)
        await DB['logs'].create_index("created_at", expireAfterSeconds=3600)
    except Exception as e:
        print(f"[INDEX] Error: {e}")
    await get_or_create_secret_key()

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
        "created_at": time.time(),
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        **details
    }
    await DB['logs'].insert_one(log_entry)

@app.get("/")
async def homepage():
    return HTMLResponse("""
<!DOCTYPE html>
<html>
<head>
    <title>SYNTAX REALM</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <style>
        *{margin:0;padding:0;box-sizing:border-box}
        body{background:linear-gradient(135deg,#0a0a0a 0%,#1a1a2e 100%);color:#fff;font-family:system-ui;display:flex;align-items:center;justify-content:center;height:100vh;overflow:hidden}
        .container{text-align:center}
        .logo-circle{width:120px;height:120px;border-radius:50%;border:3px solid #2563eb;margin:0 auto 1.5rem;overflow:hidden;box-shadow:0 0 30px rgba(37,99,235,0.3)}
        .logo-circle img{width:100%;height:100%;object-fit:cover}
        .brand{font-size:3rem;font-weight:800;letter-spacing:8px;background:linear-gradient(90deg,#2563eb,#7c3aed);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
        .sub{font-size:1.5rem;font-weight:300;color:#888;letter-spacing:4px;margin-top:0.5rem}
        .status{margin-top:2rem;display:inline-flex;align-items:center;gap:8px;background:#111;padding:10px 20px;border-radius:50px;border:1px solid #222}
        .dot{width:10px;height:10px;background:#22c55e;border-radius:50%;animation:pulse 2s infinite}
        @keyframes pulse{0%,100%{opacity:1}50%{opacity:0.5}}
        .status-text{color:#888;font-size:0.9rem}
    </style>
</head>
<body>
    <div class="container">
        <div class="logo-circle">
            <img src="https://i.ibb.co/placeholder.png" alt="Logo" onerror="this.src='data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><rect fill=%22%232563eb%22 width=%22100%22 height=%22100%22/><text x=%2250%22 y=%2255%22 text-anchor=%22middle%22 fill=%22white%22 font-size=%2240%22 font-family=%22system-ui%22>S</text></svg>'">
        </div>
        <h1 class="brand">SYNTAX</h1>
        <p class="sub">REALM</p>
        <div class="status">
            <div class="dot"></div>
            <span class="status-text">Server is Live</span>
        </div>
    </div>
</body>
</html>
    """)

@app.get("/api")
async def create_link(request: Request, api: str = Query(None), url: str = Query(None)):
    if api != ADMIN_API_KEY: return JSONResponse({"error": "auth"}, 403)
    rid = secrets.token_urlsafe(8)
    token = encrypt_token({"i": rid, "t": int(time.time())})
    await DB['links'].update_one({"random_id": rid}, {"$set": {"original_url": url, "created_at": time.time(), "clicks": 0}}, upsert=True)
    
    base = str(request.base_url).rstrip("/").replace("http://", "https://") if "localhost" not in str(request.base_url) else str(request.base_url).rstrip("/")
    red_url = f"{base}/redirect?token={token}"
    
    final = red_url
    shortener_domain, shortener_api = get_random_shortener()
    if shortener_domain and shortener_api:
        try:
            with urllib.request.urlopen(f"https://{shortener_domain}/api?api={shortener_api}&url={quote(red_url)}", timeout=5) as r:
                d = json.loads(r.read().decode())
                if d.get("status") == "success": final = d.get("shortenedUrl")
        except: pass
    return {"status": "success", "shortenedUrl": final, "directUrl": red_url}

@app.get("/redirect")
async def redirect_page(request: Request, token: str = Query(None)):
    if not token: return HTMLResponse("Blocked", 403)
    
    await log_request(request, "REDIRECT_PAGE_HIT", {"token": token[:20]})
    
    data = decrypt_token(token)
    if not data: return HTMLResponse("Invalid Token", 403)
    
    token_time = data.get("t", 0)
    if time.time() - token_time > TOKEN_EXPIRY_SECONDS:
        await log_request(request, "TOKEN_EXPIRED", {"age": int(time.time() - token_time)})
        return HTMLResponse("Link Expired. Please get a new link.", 403)
    
    link = await DB['links'].find_one({"random_id": data.get("i")})
    if not link: return HTMLResponse("Link Not Found", 404)

    referer = request.headers.get("referer", "")
    has_valid_referer = len(referer.strip()) > 0
    
    await log_request(request, "REFERER_CHECK", {"referer_value": referer[:50], "is_valid": has_valid_referer})
    
    try:
        session_id = secrets.token_hex(24)
        csrf = secrets.token_urlsafe(16)
        n1, n2 = secrets.randbelow(50)+1, secrets.randbelow(50)+1
        
        await DB['sessions'].insert_one({
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
    <title>Verifying...</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <style>
        body{{background:#0a0a0a;color:#fff;font-family:system-ui;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}}
        .box{{background:#111;border:1px solid #222;padding:2rem;border-radius:12px;text-align:center;width:320px}}
        .spinner{{width:40px;height:40px;border:4px solid #333;border-top:4px solid #2563eb;border-radius:50%;animation:spin 1s linear infinite;margin:0 auto 1rem}}
        @keyframes spin{{from{{transform:rotate(0deg)}}to{{transform:rotate(360deg)}}}}
        #status{{color:#888;font-size:0.95rem;margin-top:1rem}}
        .error{{color:#ef4444;font-weight:600}}
        .success{{color:#22c55e}}
        #errorBox{{display:none;background:#1a0a0a;border:1px solid #ef4444;padding:1rem;border-radius:8px;margin-top:1rem}}
    </style>
</head>
<body>
    <div class="box">
        <div id="loader">
            <div class="spinner"></div>
            <h2>🔐 Verifying...</h2>
            <p id="status">Please wait...</p>
        </div>
        <div id="errorBox">
            <h2 style="color:#ef4444">❌ Access Denied</h2>
            <p id="errorMsg" style="color:#888;font-size:0.9rem"></p>
        </div>
    </div>
    <script>
        const S = {{ sid: "{session_id}", csrf: "{csrf}", n1: {n1}, n2: {n2} }};

        function getFingerprint() {{
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            ctx.textBaseline = 'top';
            ctx.font = '14px Arial';
            ctx.fillText('fp', 2, 2);
            const canvasHash = canvas.toDataURL().slice(-50);
            const gl = canvas.getContext('webgl');
            let webglHash = 'none';
            if(gl) {{
                const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
                if(debugInfo) webglHash = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) || 'x';
            }}
            return btoa(canvasHash + '|' + webglHash + '|' + navigator.hardwareConcurrency + '|' + screen.width);
        }}

        async function autoVerify() {{
            document.getElementById('status').innerText = 'Setting up...';
            
            await new Promise(r => setTimeout(r, 500));
            const fingerprint = getFingerprint();
            document.cookie = "v_init=" + S.sid + ";path=/;max-age=300;SameSite=Lax";
            
            document.getElementById('status').innerText = 'Verifying...';
            
            const ans = S.n1 * S.n2;
            try {{
                const res = await fetch('/verify', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json', 'X-CSRF': S.csrf }},
                    body: JSON.stringify({{ sid: S.sid, ans: ans.toString(), fp: fingerprint }})
                }});
                const d = await res.json();
                if(d.success) {{
                    document.getElementById('status').innerHTML = '<span class="success">✓ Verified! Redirecting...</span>';
                    setTimeout(() => window.location.href = d.url, 500);
                }} else {{
                    showError(d.message);
                }}
            }} catch(e) {{
                showError('Network error. Please try again.');
            }}
        }}

        function showError(msg) {{
            document.getElementById('loader').style.display = 'none';
            document.getElementById('errorBox').style.display = 'block';
            document.getElementById('errorMsg').innerText = msg;
        }}

        autoVerify();
    </script>
</body>
</html>
    """)

@app.post("/verify")
async def verify(request: Request, v_init: str = Cookie(None)):
    try:
        body = await request.json()
        sid, ans = body.get("sid"), body.get("ans")
        fingerprint = body.get("fp")
        csrf = request.headers.get("X-CSRF")
        
        await log_request(request, "VERIFY_ATTEMPT", {"sid": sid[:20] if sid else "NONE", "has_fp": bool(fingerprint)})
        
        if not v_init or v_init != sid:
            await log_request(request, "VERIFY_FAIL", {"reason": "Cookie mismatch"})
            return JSONResponse({"success": False, "message": "Browser verification failed."}, 403)
        
        if not fingerprint or len(fingerprint) < 20:
            await log_request(request, "VERIFY_FAIL", {"reason": "Invalid fingerprint"})
            return JSONResponse({"success": False, "message": "Browser fingerprint invalid."}, 403)
        
        session = await DB['sessions'].find_one({"session_id": sid, "used": False})
        if not session:
            await log_request(request, "VERIFY_FAIL", {"reason": "Session not found"})
            return JSONResponse({"success": False, "message": "Session expired"}, 403)
        
        if not session.get("valid_referer"):
            await log_request(request, "VERIFY_FAIL", {"reason": "Invalid referer"})
            return JSONResponse({"success": False, "message": "Direct access blocked. Use shortener link."}, 403)
        
        if session["ip"] != get_ip(request):
            await log_request(request, "VERIFY_FAIL", {"reason": "IP mismatch"})
            return JSONResponse({"success": False, "message": "Network changed"}, 403)
        
        if not hmac.compare_digest(session["csrf"], csrf or ""):
            return JSONResponse({"success": False, "message": "Security error"}, 403)
        if not hmac.compare_digest(session["ans"], ans or ""):
            return JSONResponse({"success": False, "message": "Verification failed"}, 403)
        
        await DB['sessions'].update_one({"session_id": sid}, {"$set": {"used": True}})
        link = await DB['links'].find_one({"random_id": session["link_id"]})
        await DB['links'].update_one({"random_id": session["link_id"]}, {"$inc": {"clicks": 1}})
        
        await log_request(request, "VERIFY_SUCCESS", {"link_id": session["link_id"]})
        
        return {"success": True, "url": link["original_url"]}
        
    except Exception as e:
        await log_request(request, "VERIFY_ERROR", {"error": str(e)})
        return JSONResponse({"success": False, "message": "Error"}, 500)

@app.get("/logs")
async def view_logs(api: str = Query(None), limit: int = Query(50)):
    if api != ADMIN_API_KEY: return JSONResponse({"error": "auth"}, 403)
    logs = await DB['logs'].find().sort("created_at", -1).limit(limit).to_list(limit)
    for log in logs:
        log["_id"] = str(log["_id"])
    return {"total": len(logs), "logs": logs}

@app.get("/cleanup")
async def cleanup_db(api: str = Query(None)):
    if api != ADMIN_API_KEY: return JSONResponse({"error": "auth"}, 403)
    logs_deleted = await DB['logs'].delete_many({})
    sessions_deleted = await DB['sessions'].delete_many({})
    return {"status": "success", "logs_deleted": logs_deleted.deleted_count, "sessions_deleted": sessions_deleted.deleted_count}

async def auto_cleanup_task():
    while True:
        await asyncio.sleep(600)
        try:
            cutoff = time.time() - 1800
            await DB['logs'].delete_many({"created_at": {"$lt": cutoff}})
            await DB['sessions'].delete_many({"used": True})
        except: pass

@app.on_event("startup")
async def start():
    await init_db()
    await DB['sessions'].delete_many({})
    await DB['logs'].delete_many({})
    asyncio.create_task(auto_cleanup_task())
    print("SERVER ONLINE")
