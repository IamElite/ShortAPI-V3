import os
import time
import secrets
from urllib.parse import quote
from fastapi import FastAPI, Request, HTTPException, Query
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel

# ================= CONFIGURATION =================
MONGO_URI = os.getenv("MONGO_URI", "mongodb+srv://hnyx:wywyw2@cluster0.9dxlslv.mongodb.net/?retryWrites=true&w=majority")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "MY_SECRET_PASS_123")
SHORTENER_DOMAIN = "nanolinks.in"
MIN_TIME_SECONDS = 15  # Minimum time required on shortener
BASE_URL = os.getenv("BASE_URL", "https://your-app-name.koyeb.app") # Tumhara Koyeb URL

# ================= DATABASE SETUP =================
client = AsyncIOMotorClient(MONGO_URI)
db = client["url_protector"]
links_col = db["links"]       # Original links store karne ke liye
sessions_col = db["sessions"] # User sessions track karne ke liye (Anti-bypass)

# Indexes create karo (TTL for auto-cleanup)
async def init_db():
    # Sessions 10 minute baad apne aap delete ho jayenge
    await sessions_col.create_index("created_at", expireAfterSeconds=600)

app = FastAPI(on_startup=[init_db])

# ================= MODELS =================
class GenerateRequest(BaseModel):
    url: str
    password: str

# ================= ROUTES =================

@app.get("/")
async def home():
    return HTMLResponse("<h1>🚀 Anti-Bypass System Active (Python + MongoDB)</h1>")

# 1. ADMIN: Link Encrypt/Generate
@app.post("/api/generate")
async def generate_link(data: GenerateRequest):
    if data.password != ADMIN_PASSWORD:
        raise HTTPException(status_code=403, detail="Wrong Password")
    
    # Unique Link ID banate hain
    link_id = secrets.token_urlsafe(6)
    
    await links_col.insert_one({
        "link_id": link_id,
        "original_url": data.url,
        "created_at": time.time()
    })
    
    # Yeh link user ko dena hai (Ya shortener me dalna hai)
    # Flow: User visits /s/link_id -> Redirects to Shortener -> Back to /verify
    
    start_url = f"{BASE_URL}/s/{link_id}"
    
    return {
        "success": True,
        "link_id": link_id,
        "start_url": start_url,
        "note": "Is start_url ko apne shortener (nanolinks) me manually daalo."
    }

# 2. START PAGE: User yahan click karega (Timer Starts Here)
@app.get("/s/{link_id}")
async def start_session(link_id: str):
    # Check agar link exist karta hai
    link_data = await links_col.find_one({"link_id": link_id})
    if not link_data:
        return HTMLResponse("<h1>❌ Invalid Link</h1>", status_code=404)

    # Naya Session create karo database mein
    session_token = secrets.token_urlsafe(16)
    
    await sessions_col.insert_one({
        "token": session_token,
        "link_id": link_id,
        "start_time": time.time(),
        "ip_verified": False,
        "created_at": time.time() # TTL index ke liye
    })

    # Verification URL jo shortener ke baad call hoga
    verify_dest = f"{BASE_URL}/verify?token={session_token}"
    
    # External Shortener ka URL banao
    # Nanolinks format: domain.com/?url={destination}&ref={something}
    # Ham destination ko encode karke bhejenge
    
    final_shortener_url = f"https://{SHORTENER_DOMAIN}/?url={quote(verify_dest)}"

    # User ko redirect page dikhao (Loader)
    html_content = f"""
    <html>
    <head>
        <title>Processing...</title>
        <meta http-equiv="refresh" content="2;url={final_shortener_url}">
        <style>
            body {{ font-family: sans-serif; text-align: center; padding: 50px; background: #f4f4f4; }}
            .loader {{ border: 5px solid #f3f3f3; border-top: 5px solid #3498db; border-radius: 50%; width: 50px; height: 50px; animation: spin 1s linear infinite; margin: 20px auto; }}
            @keyframes spin {{ 0% {{ transform: rotate(0deg); }} 100% {{ transform: rotate(360deg); }} }}
        </style>
    </head>
    <body>
        <div class="loader"></div>
        <h3>Security Check...</h3>
        <p>Redirecting to shortener...</p>
    </body>
    </html>
    """
    return HTMLResponse(html_content)

# 3. VERIFY PAGE: Shortener se wapas aane par
@app.get("/verify")
async def verify_session(token: str = Query(...)):
    # Database me session dhundo
    session = await sessions_col.find_one({"token": token})
    
    if not session:
        return HTMLResponse("<h1>🚫 Session Expired or Invalid. Try again.</h1>", status_code=400)

    # Time calculate karo (Server Time vs Session Start Time)
    time_spent = time.time() - session["start_time"]
    
    # Check Time Logic
    if time_spent < MIN_TIME_SECONDS:
        return HTMLResponse(f"""
            <div style="text-align:center; padding:50px; font-family:sans-serif;">
                <h1 style="color:red">🚫 Too Fast!</h1>
                <p>You spent only {int(time_spent)} seconds.</p>
                <p>Minimum requirement is {MIN_TIME_SECONDS} seconds.</p>
                <p>Please go back and complete the steps properly.</p>
            </div>
        """, status_code=403)

    # Original Link nikalo
    link_data = await links_col.find_one({"link_id": session["link_id"]})
    
    if not link_data:
        return HTMLResponse("<h1>❌ Original Link Not Found</h1>", status_code=404)

    # Session delete karo (One-time use security)
    # Agar user link share karega to dusre ke liye open nahi hoga
    await sessions_col.delete_one({"_id": session["_id"]})

    # Success Page & Redirect
    return HTMLResponse(f"""
    <html>
    <head>
        <title>Success ✅</title>
        <style>
            body {{ font-family: sans-serif; text-align: center; padding: 50px; background: #e8f5e9; }}
            .box {{ background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); display: inline-block; }}
        </style>
    </head>
    <body>
        <div class="box">
            <h1 style="color: green;">✅ Verified!</h1>
            <p>Time Validated: {int(time_spent)} seconds</p>
            <p>Redirecting to your destination...</p>
        </div>
        <script>
            setTimeout(() => {{
                window.location.href = "{link_data['original_url']}";
            }}, 2000);
        </script>
    </body>
    </html>
    """)
