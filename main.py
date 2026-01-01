import random, os, time, secrets, json, base64, hashlib, hmac, urllib.request, asyncio
from urllib.parse import quote, urlparse
from fastapi import FastAPI, Request, Query, Cookie
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient

MONGO_URI_1 = os.getenv("MONGO_URI_1", "mongodb+srv://hnyx:wywyw2@cluster0.9dxlslv.mongodb.net/?retryWrites=true&w=majority")
MONGO_URI_2 = os.getenv("MONGO_URI_2", "mongodb+srv://public:abishnoimf@cluster0.rqk6ihd.mongodb.net/?retryWrites=true&w=majority")
MONGO_URI_3 = os.getenv("MONGO_URI_3", "mongodb+srv://ravi:ravi12345@cluster0.hndinhj.mongodb.net/?retryWrites=true&w=majority")

ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "DurgeshShornerApi")

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
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SYNTAX REALM | LIVE</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; font-family: 'Inter', system-ui, sans-serif; }
        
        body {
            background: #020205; color: #fff; height: 100dvh;
            display: flex; align-items: center; justify-content: center; overflow: hidden;
        }

        .bg {
            position: absolute; inset: 0; z-index: -1;
            background: radial-gradient(circle at 20% 30%, #1e3a8a 0%, transparent 40%),
                        radial-gradient(circle at 80% 70%, #581c87 0%, transparent 40%);
            filter: blur(60px); opacity: 0.6; animation: move 10s ease infinite alternate;
        }
        @keyframes move { from { transform: scale(1); } to { transform: scale(1.2); } }

        .container {
            text-align: center; width: 90%; max-width: 500px;
            display: flex; flex-direction: column; align-items: center; gap: 20px;
        }

        .logo {
            width: clamp(160px, 45vw, 220px); height: clamp(160px, 45vw, 220px);
            border-radius: 50%; border: 3px solid #3b82f6; padding: 6px;
            box-shadow: 0 0 40px rgba(59, 130, 246, 0.4);
            animation: float 4s ease-in-out infinite;
        }
        .logo img { width: 100%; height: 100%; border-radius: 50%; object-fit: cover; }
        @keyframes float { 0%, 100% { transform: translateY(0); } 50% { transform: translateY(-15px); } }

        .name {
            font-size: clamp(2rem, 8vw, 3.5rem); font-weight: 900; letter-spacing: 4px;
            color: #ffffff;
            animation: grow 3s ease-in-out infinite alternate;
        }
        @keyframes shine { to { background-position: 200%; } }
        @keyframes grow { from { transform: scale(1); } to { transform: scale(1.05); } }

        .status {
            display: flex; align-items: center; gap: 8px; color: #22c55e;
            font-size: 0.8rem; font-weight: 800; letter-spacing: 2px;
        }
        .dot { width: 8px; height: 8px; background: #22c55e; border-radius: 50%; box-shadow: 0 0 10px #22c55e; animation: blink 1s infinite; }
        @keyframes blink { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }

        .btn-group { display: flex; gap: 15px; margin-top: 15px; width: 100%; justify-content: center; flex-wrap: wrap; }
        
        .btn {
            text-decoration: none; padding: 12px 25px; border-radius: 12px;
            font-size: 0.9rem; font-weight: 600; transition: 0.3s;
            border: 1px solid rgba(255,255,255,0.1); backdrop-filter: blur(10px);
        }
        .btn-primary { background: #3b82f6; color: white; box-shadow: 0 10px 20px -5px rgba(59,130,246,0.5); }
        .btn-secondary { background: rgba(255,255,255,0.05); color: white; }
        
        .btn:hover { transform: translateY(-3px); filter: brightness(1.2); }
    </style>
</head>
<body>
    <div class="bg"></div>
    <div class="container">
        <div class="logo">
            <img src="https://i.pinimg.com/736x/58/ee/c5/58eec56f64d919b5e1a820f169c8db16.jpg" alt="Logo">
        </div>
        
        <h1 class="name">SYNTAX REALM</h1>
        
        <div class="status"><div class="dot"></div> SERVER IS LIVE</div>

        <div class="btn-group">
            <a href="https://t.me/SyntaxRealm" target="_blank" class="btn btn-primary">Join Community</a>
            <a href="https://t.me/PookieRealm" target="_blank" class="btn btn-secondary">View Work</a>
        </div>
    </div>
</body>
</html>
    """)

@app.get("/api")
async def create_link(request: Request, api: str = Query(None), url: str = Query(None), alias: str = Query(None), expiry: int = Query(0), password: str = Query(None), custom_base: str = Query(None), custom_api: str = Query(None)):
    base = str(request.base_url).rstrip("/")
    if "localhost" not in base:
        base = base.replace("http://", "https://")
    
    if not api and not custom_base:
        return {
            "documentation": {
                "create_api": f"{base}/api",
                "basic": f"{base}/api?api={ADMIN_API_KEY}&url=https://google.com",
                "withAlias": f"{base}/api?api={ADMIN_API_KEY}&url=https://google.com&alias=mylink",
                "withExpiry": f"{base}/api?api={ADMIN_API_KEY}&url=https://google.com&expiry=7",
                "withPassword": f"{base}/api?api={ADMIN_API_KEY}&url=https://google.com&password=secret123",
                "advanced": f"{base}/api?api={ADMIN_API_KEY}&url=https://google.com&alias=mylink&expiry=7&password=secret",
                "customProvider": f"{base}/api?custom_base=https://{SHORT_BASE_1}&custom_api={SHORT_API_1}&url=https://google.com",
                "customProvider2": f"{base}/api?custom_base={SHORT_BASE_1}&custom_api={SHORT_API_1}&url=https://google.com",
                "customProviderAdvanced": f"{base}/api?custom_base=https://{SHORT_BASE_1}&custom_api={SHORT_API_1}&url=https://google.com&alias=mylink&expiry=7&password=secret"
            },
            "examples": {
                "basic": f"{base}/api?api={ADMIN_API_KEY}&url=https://google.com",
                "advanced": f"{base}/api?api={ADMIN_API_KEY}&url=https://google.com&alias=mylink&expiry=7&password=secret",
                "custom_provider_basic": f"{base}/api?custom_base=https://{SHORT_BASE_1}&custom_api={SHORT_API_1}&url=https://google.com",
                "custom_provider_advanced": f"{base}/api?custom_base=https://{SHORT_BASE_1}&custom_api={SHORT_API_1}&url=https://google.com&alias=mylink&expiry=7&password=secret"
            },
            "endpoints": {
                "analytics": f"{base}/analytics/TOKEN",
                "qrCode": f"{base}/qr/TOKEN",
                "logs": f"{base}/logs?api={ADMIN_API_KEY}",
                "cleanup": f"{base}/cleanup?api={ADMIN_API_KEY}"
            }
        }
    
    if not url:
        return JSONResponse({"status": "error", "message": "Missing URL parameter"}, 400)
    
    # Custom provider mode OR Admin mode
    is_custom_mode = bool(custom_base and custom_api)
    
    if not is_custom_mode:
        if api != ADMIN_API_KEY:
            return JSONResponse({"status": "error", "message": "Invalid API Key"}, 401)
    
    rid = alias if alias else secrets.token_urlsafe(8)
    
    # Calculate expiry timestamp
    expiry_time = None
    if expiry > 0:
        expiry_time = time.time() + (expiry * 24 * 60 * 60)
    
    # Store link data
    link_data = {
        "original_url": url,
        "created_at": time.time(),
        "clicks": 0,
        "password": password,
        "expiry": expiry_time,
        "alias": alias
    }
    await DB['links'].update_one({"random_id": rid}, {"$set": link_data}, upsert=True)
    
    # Create token
    token_data = {"i": rid, "t": int(time.time())}
    if password:
        token_data["p"] = password
    if expiry_time:
        token_data["e"] = expiry_time
    token = encrypt_token(token_data)
    
    red_url = f"{base}/redirect?token={token}"
    
    # Use custom provider or default providers
    final = red_url
    if is_custom_mode:
        try:
            provider_url = custom_base if custom_base.startswith("http") else f"https://{custom_base}"
            if not provider_url.endswith("/api"):
                provider_url = provider_url.rstrip("/") + "/api"
            fetch_url = f"{provider_url}?api={custom_api}&url={quote(url)}"
            if alias:
                fetch_url += f"&alias={quote(alias)}"
            with urllib.request.urlopen(fetch_url, timeout=5) as r:
                d = json.loads(r.read().decode())
                if d.get("status") == "success":
                    final = d.get("shortenedUrl") or d.get("shortUrl") or d.get("url")
        except Exception as e:
            return JSONResponse({"status": "error", "message": f"Provider error: {str(e)}"}, 502)
    else:
        shortener_domain, shortener_api = get_random_shortener()
        used_provider = shortener_domain or "None"
        if shortener_domain and shortener_api:
            try:
                fetch_url = f"https://{shortener_domain}/api?api={shortener_api}&url={quote(red_url)}"
                if alias:
                    fetch_url += f"&alias={quote(alias)}"
                with urllib.request.urlopen(fetch_url, timeout=5) as r:
                    d = json.loads(r.read().decode())
                    if d.get("status") == "success":
                        final = d.get("shortenedUrl")
            except:
                pass
    
    qr_image_url = f"https://api.qrserver.com/v1/create-qr-code/?size=300x300&data={quote(red_url)}"
    
    return {
        "status": "success",
        "shortenedUrl": final,
        "directUrl": red_url,
        "qrCode": qr_image_url,
        "analytics": f"{base}/analytics/{token}",
        "mode": f"Custom Provider ({urlparse(custom_base).netloc or custom_base.replace('https://','').replace('http://','').split('/')[0]})" if is_custom_mode else f"Default Provider ({used_provider})",
        "config": {
            "alias": alias or "auto-generated",
            "expiry": f"{expiry} days" if expiry > 0 else "Never",
            "passwordProtection": bool(password)
        }
    }

@app.get("/redirect")
async def redirect_page(request: Request, token: str = Query(None)):
    if not token: return HTMLResponse("Blocked", 403)
    
    await log_request(request, "REDIRECT_PAGE_HIT", {"token": token[:20]})
    
    data = decrypt_token(token)
    if not data: return HTMLResponse("Invalid Token", 403)
    
    token_time = data.get("t", 0)
    if time.time() - token_time > TOKEN_EXPIRY_SECONDS:
        await log_request(request, "TOKEN_EXPIRED", {"age": int(time.time() - token_time)})
        return HTMLResponse("""
<!DOCTYPE html>
<html>
<head>
    <title>Link Expired</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            background: #050505;
            font-family: 'Inter', system-ui, sans-serif;
            display: flex;
            align-items: center;
            justify-content: center;
            height: 100vh;
            color: white;
        }
        .card {
            background: rgba(15, 15, 15, 0.95);
            padding: clamp(25px, 5vw, 40px);
            border-radius: 24px;
            text-align: center;
            max-width: 380px;
            width: 90%;
            border: 1px solid #333;
            box-shadow: 0 20px 40px rgba(0,0,0,0.5);
        }
        .icon { font-size: clamp(40px, 12vw, 60px); margin-bottom: clamp(12px, 3vw, 20px); }
        h1 { color: #fbbf24; font-size: clamp(1.2rem, 5vw, 1.5rem); margin-bottom: clamp(10px, 2vw, 15px); }
        p { color: #888; font-size: clamp(0.8rem, 3vw, 0.95rem); line-height: 1.6; margin-bottom: clamp(15px, 4vw, 25px); }
        .btn {
            background: #fbbf24;
            color: #000;
            border: none;
            padding: 14px 28px;
            border-radius: 12px;
            font-weight: 700;
            cursor: pointer;
            font-size: 1rem;
            text-decoration: none;
            display: inline-block;
            transition: 0.3s;
        }
        .btn:hover { background: #f59e0b; transform: scale(1.03); }
    </style>
</head>
<body>
    <div class="card">
        <div class="icon">⏰</div>
        <h1>Link Expired</h1>
        <p>This link has expired. Please request a new link from the original source.</p>
        <a href="javascript:window.close()" class="btn">Close Tab</a>
    </div>
</body>
</html>
        """, 403)
    
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
    <title>Access Denied</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <style>
        @keyframes fadeInZoom {{
            from {{ opacity: 0; transform: scale(0.9) translateY(20px); }}
            to {{ opacity: 1; transform: scale(1) translateY(0); }}
        }}
        @keyframes glowPulse {{
            0%, 100% {{ border-color: rgba(255, 71, 87, 0.2); box-shadow: 0 0 20px rgba(0,0,0,0.8); }}
            50% {{ border-color: rgba(255, 71, 87, 0.5); box-shadow: 0 0 30px rgba(255, 71, 87, 0.2); }}
        }}
        @keyframes floating {{
            0% {{ transform: translateY(0px); }}
            50% {{ transform: translateY(-10px); }}
            100% {{ transform: translateY(0px); }}
        }}
        @keyframes starMove {{
            from {{ transform: translateY(0); }}
            to {{ transform: translateY(-100vh); }}
        }}
        @keyframes spin {{
            from {{ transform: rotate(0deg); }}
            to {{ transform: rotate(360deg); }}
        }}
        @keyframes blink {{ 0%, 100% {{ opacity: 1; }} 50% {{ opacity: 0.4; }} }}
        
        body {{
            background-color: #050505;
            font-family: 'Inter', system-ui, sans-serif;
            margin: 0;
            display: flex;
            align-items: center;
            justify-content: center;
            height: 100vh;
            overflow: hidden;
            color: white;
        }}
        .bg-animation {{
            position: fixed;
            top: 0; left: 0; width: 100%; height: 100%;
            background: radial-gradient(circle at center, #1a0505 0%, #050505 100%);
            z-index: -1;
        }}
        .stars {{
            width: 2px; height: 2px;
            background: transparent;
            box-shadow: 10vw 20vh #ff4757, 50vw 40vh #ff4757, 80vw 10vh #fff, 30vw 90vh #ff4757;
            animation: starMove 20s linear infinite;
        }}
        #loader {{
            text-align: center;
        }}
        .spinner {{
            width: 40px; height: 40px;
            border: 4px solid #333;
            border-top: 4px solid #ff4757;
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin: 0 auto 1rem;
        }}
        #status {{ color: #888; font-size: 0.95rem; margin-top: 1rem; }}
        .success {{ color: #22c55e; }}
        .alert-card {{
            background: rgba(15, 15, 15, 0.9);
            padding: clamp(25px, 6vw, 40px) clamp(20px, 5vw, 30px);
            border-radius: clamp(20px, 5vw, 30px);
            text-align: center;
            max-width: 340px;
            width: 85%;
            border: 1px solid rgba(255, 71, 87, 0.2);
            backdrop-filter: blur(15px);
            animation: fadeInZoom 0.8s ease-out forwards, glowPulse 3s infinite ease-in-out;
        }}
        .header-text {{
            color: #ff4757;
            font-size: clamp(1.2rem, 5vw, 1.5rem);
            margin: 0 0 clamp(12px, 3vw, 20px) 0;
            font-weight: 800;
            text-shadow: 0 0 10px rgba(255, 71, 87, 0.4);
        }}
        .content-body {{ margin: clamp(12px, 3vw, 20px) 0; }}
        .main-msg {{ color: #ccc; font-size: clamp(0.85rem, 3vw, 1rem); margin: 0.5rem 0; font-weight: 500; }}
        .era-text {{ color: #888; font-size: clamp(0.75rem, 2.5vw, 0.9rem); }}
        .sticker-wrapper {{
            width: clamp(100px, 30vw, 150px); height: clamp(100px, 30vw, 150px);
            margin: clamp(10px, 2vw, 15px) auto clamp(15px, 4vw, 25px);
            overflow: hidden;
            border-radius: clamp(15px, 4vw, 25px);
            background: rgba(255, 255, 255, 0.02);
            animation: floating 4s infinite ease-in-out;
            box-shadow: 0 10px 20px rgba(0,0,0,0.5);
        }}
        .tg-video-sticker {{ width: 100%; height: 100%; object-fit: cover; }}
        .status-badge {{
            background: rgba(255, 255, 255, 0.05);
            padding: clamp(8px, 2vw, 10px) clamp(12px, 3vw, 18px);
            border-radius: 15px;
            font-size: clamp(0.7rem, 2.5vw, 0.85rem);
            color: #aaa;
            display: inline-flex;
            align-items: center;
            gap: clamp(6px, 2vw, 10px);
            margin-bottom: clamp(20px, 5vw, 30px);
            border: 1px solid #222;
        }}
        .dot {{
            width: 8px; height: 8px;
            background: #ff4757;
            border-radius: 50%;
            box-shadow: 0 0 10px #ff4757;
            animation: blink 1s infinite;
        }}
        .action-btn {{
            background: #ffffff;
            color: #000;
            border: none;
            padding: clamp(12px, 3vw, 16px);
            border-radius: clamp(12px, 3vw, 18px);
            font-weight: 800;
            cursor: pointer;
            width: 100%;
            font-size: clamp(0.85rem, 3vw, 1rem);
            transition: 0.3s all;
        }}
        .action-btn:hover {{
            background: #ff4757;
            color: white;
            transform: scale(1.03);
            box-shadow: 0 0 20px rgba(255, 71, 87, 0.4);
        }}
        .footer-credit {{ margin-top: 25px; font-size: 0.8rem; color: #555; }}
        .footer-credit a {{ color: #ff4757; text-decoration: none; font-weight: bold; }}
        #errorBox {{ display: none; }}
    </style>
</head>
<body>
    <div class="bg-animation"><div class="stars"></div></div>
    
    <div id="loader" class="alert-card">
        <div class="spinner"></div>
        <h2 style="color:#fff">🔐 Verifying...</h2>
        <p id="status">Please wait...</p>
    </div>
    
    <div id="errorBox" class="alert-card">
        <h1 class="header-text">🚨 Bypass Detected 🚨</h1>
        <div class="content-body">
            <p class="main-msg">"Focus on Life, not bypass"</p>
            <p class="era-text">(Era of Anti-Bypass)</p>
        </div>
        <div class="sticker-wrapper">
            <video autoplay loop muted playsinline class="tg-video-sticker">
                <source src="https://files.catbox.moe/1oyunr.webm" type="video/webm">
            </video>
        </div>
        <div class="status-badge">
            <span class="dot"></span>
            Attempt Logged: <span id="timestamp"></span>
        </div>
        <button class="action-btn" onclick="window.history.back()">Exit Immediately</button>
        <p class="footer-credit">Access Denied By <a href="https://t.me/DshDm_bot" target="_blank">Durgesh</a></p>
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
                    showError();
                }}
            }} catch(e) {{
                showError();
            }}
        }}

        function showError() {{
            document.getElementById('loader').style.display = 'none';
            document.getElementById('errorBox').style.display = 'block';
            document.getElementById('timestamp').innerText = new Date().toLocaleTimeString().toLowerCase();
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

@app.get("/analytics/{token}")
async def analytics(token: str):
    try:
        data = decrypt_token(token)
        if not data:
            return JSONResponse({"status": "error", "message": "Invalid Token"}, 400)
        
        link = await DB['links'].find_one({"random_id": data.get("i")})
        
        expiry_date = None
        is_expired = False
        if data.get("e"):
            expiry_date = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(data["e"]))
            is_expired = time.time() > data["e"]
        
        return {
            "status": "success",
            "link_info": {
                "destination": link["original_url"] if link else "Unknown",
                "alias": link.get("alias") if link else None,
                "password_protected": bool(data.get("p")),
                "expiry_date": expiry_date or "Never",
                "is_expired": is_expired,
                "clicks": link.get("clicks", 0) if link else 0,
                "created_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(link["created_at"])) if link else None
            }
        }
    except:
        return JSONResponse({"status": "error", "message": "Error reading token"}, 500)

@app.get("/qr/{token}")
async def qr_code(request: Request, token: str):
    base = str(request.base_url).rstrip("/")
    if "localhost" not in base:
        base = base.replace("http://", "https://")
    target_url = f"{base}/redirect?token={token}"
    qr_api_url = f"https://api.qrserver.com/v1/create-qr-code/?size=300x300&data={quote(target_url)}&bgcolor=ffffff&color=000000"
    return JSONResponse({"status": "success", "qr_image": qr_api_url, "target_url": target_url})

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
