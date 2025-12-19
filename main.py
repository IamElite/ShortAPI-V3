import os
import time
import secrets
import json
import urllib.request
import re
from urllib.parse import quote
from fastapi import FastAPI, Request, Query, Response, HTTPException, Depends
from fastapi.responses import HTMLResponse, JSONResponse
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel

# ================= CONFIGURATION =================
MONGO_URI = os.getenv("MONGO_URI", "mongodb+srv://hnyx:wywyw2@cluster0.9dxlslv.mongodb.net/?retryWrites=true&w=majority")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "MY_SECRET_PASS_123")
SHORTENER_DOMAIN = "nanolinks.in"
SHORTENER_API = "ae0271c2c57105db2fa209f5b0f20c1a965343f6"

# Security Configurations
MIN_WAIT_TIME = 8  # Seconds (User must spend at least this time)
SESSION_EXPIRY = 300  # 5 Minutes (Token expires after this)
COOKIE_NAME = "secure_client_session"

# ================= DATABASE SETUP =================
client = AsyncIOMotorClient(MONGO_URI)
db = client["url_protector_db"]
links_col = db["links"]
sessions_col = db["sessions"]

# Regex for detecting common bots
BOT_REGEX = re.compile(r"(curl|wget|python|bot|spider|crawler|scraper|headless)", re.IGNORECASE)

async def init_db():
    # 1. Sessions cleanup: 5 Minute (300s) mein expire (Strict Security)
    try:
        await sessions_col.create_index("created_at", expireAfterSeconds=SESSION_EXPIRY)
    except:
        pass

    # 2. Links cleanup: 30 Din mein expire
    try:
        await links_col.create_index("created_at", expireAfterSeconds=2592000)
    except:
        pass

app = FastAPI(on_startup=[init_db])

# ================= HELPER FUNCTIONS =================

def get_base_url(request: Request):
    """Detects the current domain and forces HTTPS."""
    url = str(request.base_url).rstrip("/")
    if "localhost" not in url and "127.0.0.1" not in url:
        url = url.replace("http://", "https://")
    return url

def is_bot(user_agent: str):
    """Checks if the request is from a known bot/script."""
    if not user_agent:
        return True  # Block requests with no User-Agent
    if len(user_agent) < 10:
        return True # Suspiciously short User-Agent
    return BOT_REGEX.search(user_agent) is not None

async def check_rate_limit(ip: str):
    """Simple rate limiter: Max 10 requests per minute per IP."""
    # Count sessions created by this IP in the last 60 seconds
    window_start = time.time() - 60
    count = await sessions_col.count_documents({
        "ip": ip,
        "created_at": {"$gte": window_start}
    })
    return count >= 10

# ================= ADMIN API (GENERATE LINKS) =================

@app.get("/api")
async def create_link(request: Request, api: str = Query(None), url: str = Query(None)):
    """Generates a protected link using the Admin Password."""
    
    # 1. Security Check
    if api != ADMIN_PASSWORD:
        return JSONResponse(content={"status": "error", "message": "Invalid API Key"}, status_code=403)
    
    if not url:
        return JSONResponse(content={"status": "error", "message": "URL missing"}, status_code=400)

    # 2. Duplicate Check (Optimization)
    existing_link = await links_col.find_one({"original_url": url})
    
    if existing_link:
        link_id = existing_link["link_id"]
        # Refresh expiry
        await links_col.update_one({"_id": existing_link["_id"]}, {"$set": {"created_at": time.time()}})
    else:
        link_id = secrets.token_urlsafe(6)
        await links_col.insert_one({
            "link_id": link_id,
            "original_url": url,
            "created_at": time.time()
        })
    
    # 3. Build URLs
    base_url = get_base_url(request)
    target_url = f"{base_url}/s/{link_id}"
    
    # 4. Integrate with Nanolinks API
    final_short_url = target_url # Fallback
    
    if SHORTENER_API:
        try:
            # Note: We encode target_url so Nanolinks processes it correctly
            api_req_url = f"https://{SHORTENER_DOMAIN}/api?api={SHORTENER_API}&url={quote(target_url)}"
            
            with urllib.request.urlopen(api_req_url) as response:
                data = json.loads(response.read().decode())
                if data.get("status") == "success":
                    final_short_url = data.get("shortenedUrl")
        except Exception as e:
            print(f"Shortener API Error: {e}")
            pass

    return {
        "status": "success",
        "shortenedUrl": final_short_url
    }

# ================= STEP 1: START SESSION (Set Cookie + Token) =================

@app.get("/s/{link_id}")
async def start_session(link_id: str, request: Request, response: Response):
    # 1. Validate User Agent (Bot Protection)
    user_agent = request.headers.get("User-Agent", "")
    if is_bot(user_agent):
        return HTMLResponse("<h1>🚫 Access Denied: Bots/Scripts not allowed.</h1>", status_code=403)

    # 2. Check Link Validity
    link_data = await links_col.find_one({"link_id": link_id})
    if not link_data:
        return HTMLResponse("<h1>❌ Invalid or Expired Link</h1>", status_code=404)

    # 3. Rate Limiting (IP Based)
    client_ip = request.client.host
    if await check_rate_limit(client_ip):
         return HTMLResponse("<h1>⏳ Too many requests. Please wait a minute.</h1>", status_code=429)

    # 4. Generate Session Security
    base_url = get_base_url(request)
    session_token = secrets.token_urlsafe(24) # The token sent to Shortener
    client_uuid = secrets.token_hex(16)       # The cookie value (Invisible to shortener)
    
    # 5. Store Session in MongoDB
    await sessions_col.insert_one({
        "token": session_token,
        "link_id": link_id,
        "client_uuid": client_uuid, # Binding token to this specific browser
        "ip": client_ip,
        "start_time": time.time(),
        "created_at": time.time(),
        "used": False
    })

    # 6. Set Secure Cookie (Critical Anti-Bypass Step)
    # httponly=True prevents JS from reading it (XSS protection)
    # samesite='lax' allows redirect flows to work
    # UPDATED: Points to /redirect now instead of /verify
    verify_url = f"{base_url}/redirect?token={session_token}"
    
    response = HTMLResponse(f"""
    <html>
    <head><meta http-equiv="refresh" content="0;url=https://{SHORTENER_DOMAIN}/?url={quote(verify_url)}"></head>
    <body>
        <h3>Securing connection...</h3>
        <p>Redirecting to provider.</p>
    </body>
    </html>
    """)
    
    response.set_cookie(
        key=COOKIE_NAME, 
        value=client_uuid, 
        httponly=True, 
        max_age=SESSION_EXPIRY,
        samesite="lax"
    )
    
    return response

# ================= STEP 2: VERIFICATION (Check Cookie + Time) =================
# Renamed from /verify to /redirect to match your flow diagram
@app.get("/redirect")
async def verify_session(request: Request, token: str = Query(...)):
    # 1. Validate User Agent again
    user_agent = request.headers.get("User-Agent", "")
    if is_bot(user_agent):
        return HTMLResponse("<h1>🚫 Bot Detected. Access Denied.</h1>", status_code=403)

    # 2. Find Session by Token
    session = await sessions_col.find_one({"token": token})
    
    if not session:
        return HTMLResponse("<h1>🚫 Invalid or Expired Session. Start again.</h1>", status_code=400)

    if session.get("used"):
        return HTMLResponse("<h1>🚫 This link has already been used.</h1>", status_code=409)

    # 3. SECURITY: Cookie Binding Check
    # Does the browser have the same cookie we set in Step 1?
    client_cookie = request.cookies.get(COOKIE_NAME)
    
    if not client_cookie or client_cookie != session.get("client_uuid"):
        # This happens if user used a bypass script or shared the verify link
        return HTMLResponse("""
            <div style="text-align:center; padding: 20px;">
                <h1 style="color:red;">🚫 Security Check Failed</h1>
                <p>Browser signature mismatch.</p>
                <p><b>Possible Reason:</b> You are using a bypass script, Incognito mode, or cookies are disabled.</p>
                <p>Please click the original link again.</p>
            </div>
        """, status_code=403)

    # 4. SECURITY: Time Check (Anti-Fast Bypass)
    time_spent = time.time() - session["start_time"]
    if time_spent < MIN_WAIT_TIME:
        return HTMLResponse(f"""
            <div style="text-align:center; padding: 20px; font-family: sans-serif;">
                <h1 style="color:orange;">⏳ Too Fast!</h1>
                <p>You arrived in {int(time_spent)} seconds.</p>
                <p>Human verification requires at least {MIN_WAIT_TIME} seconds.</p>
                <p>Please go back and wait on the shortener page.</p>
            </div>
        """, status_code=429)

    # 5. Success! Get Original Link
    link_data = await links_col.find_one({"link_id": session["link_id"]})
    
    if not link_data:
        return HTMLResponse("<h1>❌ Original Link Not Found</h1>", status_code=404)

    # 6. Mark Session as Used (Prevents Replay Attacks)
    await sessions_col.update_one({"_id": session["_id"]}, {"$set": {"used": True}})
    
    # 7. Final Redirect
    return HTMLResponse(f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Success</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            body {{ font-family: sans-serif; text-align: center; padding: 20px; background: #e8f5e9; }}
            .box {{ background: white; padding: 40px; border-radius: 15px; max-width: 500px; margin: 50px auto; box-shadow: 0 4px 15px rgba(0,0,0,0.1); }}
        </style>
        <script>
            setTimeout(() => {{
                window.location.href = "{link_data['original_url']}";
            }}, 1500);
        </script>
    </head>
    <body>
        <div class="box">
            <h1 style="color: #27ae60;">✅ Verified</h1>
            <p>Security checks passed.</p>
            <p>Redirecting to destination...</p>
        </div>
    </body>
    </html>
    """)

@app.get("/")
async def home():
    return {"message": "Secure Anti-Bypass System Active v2.0", "status": "Running"}
