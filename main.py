import os
import time
import secrets
import json
import urllib.request
from urllib.parse import quote
from fastapi import FastAPI, Request, Query
from fastapi.responses import HTMLResponse, JSONResponse
from motor.motor_asyncio import AsyncIOMotorClient

# ================= CONFIGURATION =================
# Mongo URI wahi jo aapne diya
MONGO_URI = os.getenv("MONGO_URI", "mongodb+srv://hnyx:wywyw2@cluster0.9dxlslv.mongodb.net/?retryWrites=true&w=majority")

# Is password ko API Key ki tarah use karein
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "MY_SECRET_PASS_123")

# Aapka Shortener Domain & API
SHORTENER_DOMAIN = "nanolinks.in"
SHORTENER_API = "ae0271c2c57105db2fa209f5b0f20c1a965343f6"

# ================= DATABASE SETUP =================
client = AsyncIOMotorClient(MONGO_URI)
db = client["url_protector_db"]
links_col = db["links"]
sessions_col = db["sessions"]

async def init_db():
    # 10 Minute session expiry
    try:
        await sessions_col.create_index("created_at", expireAfterSeconds=600)
    except:
        pass

app = FastAPI(on_startup=[init_db])

# ================= HELPER =================
def get_base_url(request: Request):
    url = str(request.base_url).rstrip("/")
    if "localhost" not in url:
        url = url.replace("http://", "https://")
    return url

# ================= API ROUTE (SIMPLE GET) =================
# Format: /api?api=PASSWORD&url=YOUR_LINK
@app.get("/api")
async def create_link(request: Request, api: str = Query(None), url: str = Query(None)):
    # 1. Check Password/API Key
    if api != ADMIN_PASSWORD:
        return JSONResponse(content={"status": "error", "message": "Invalid API Key"}, status_code=403)
    
    if not url:
        return JSONResponse(content={"status": "error", "message": "URL missing"}, status_code=400)

    # 2. Save to DB
    link_id = secrets.token_urlsafe(6)
    await links_col.insert_one({
        "link_id": link_id,
        "original_url": url,
        "created_at": time.time()
    })
    
    # 3. Generate Response
    base_url = get_base_url(request)
    # The "Start Page" URL that needs to be shortened
    target_url = f"{base_url}/s/{link_id}"
    
    # 4. Call Shortener API (Nanolinks)
    final_short_url = target_url # Default fallback
    
    if SHORTENER_API:
        try:
            # Construct API call to Nanolinks
            api_req_url = f"https://{SHORTENER_DOMAIN}/api?api={SHORTENER_API}&url={quote(target_url)}"
            
            # Make the request (using standard library to avoid extra dependencies)
            with urllib.request.urlopen(api_req_url) as response:
                data = json.loads(response.read().decode())
                if data.get("status") == "success":
                    final_short_url = data.get("shortenedUrl")
        except Exception as e:
            print(f"Shortener API Error: {e}")
            # If API fails, we still return our local URL so the process doesn't break
            pass

    # EXACT JSON FORMAT JO AAPNE MANGA
    return {
        "status": "success",
        "shortenedUrl": final_short_url
    }

# ================= USER ROUTES (DO NOT CHANGE) =================

@app.get("/s/{link_id}")
async def start_session(link_id: str, request: Request):
    # Check link
    if not await links_col.find_one({"link_id": link_id}):
        return HTMLResponse("Invalid Link", status_code=404)

    # Session Start
    base_url = get_base_url(request)
    session_token = secrets.token_urlsafe(16)
    
    await sessions_col.insert_one({
        "token": session_token,
        "link_id": link_id,
        "start_time": time.time(),
        "created_at": time.time()
    })

    # Shortener Logic
    verify_url = f"{base_url}/verify?token={session_token}"
    final_url = f"https://{SHORTENER_DOMAIN}/?url={quote(verify_url)}"

    return HTMLResponse(f"""
    <html>
    <head><meta http-equiv="refresh" content="0;url={final_url}"></head>
    <body>Redirecting to secure link...</body>
    </html>
    """)

@app.get("/verify")
async def verify_session(token: str = Query(...)):
    session = await sessions_col.find_one({"token": token})
    if not session:
        return HTMLResponse("Session Expired", status_code=400)

    # Time Check Removed as per request
    
    # Get Original Link
    link_data = await links_col.find_one({"link_id": session["link_id"]})
    await sessions_col.delete_one({"_id": session["_id"]}) # Security: Delete token

    # Success Redirect
    return HTMLResponse(f"""
    <html>
    <script>window.location.href = "{link_data['original_url']}";</script>
    <body>Redirecting...</body>
    </html>
    """)

@app.get("/")
async def home():
    return {"message": "System Active", "usage": "/api?api=PASS&url=LINK"}
