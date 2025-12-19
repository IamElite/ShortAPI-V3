import os
import time
import secrets
from urllib.parse import quote
from fastapi import FastAPI, Request, HTTPException, Query
from fastapi.responses import HTMLResponse
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel

# ================= CONFIGURATION =================
# Your provided MongoDB URI
MONGO_URI = os.getenv("MONGO_URI", "mongodb+srv://hnyx:wywyw2@cluster0.9dxlslv.mongodb.net/?retryWrites=true&w=majority")

# Admin Password to generate links (You can change this)
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "MY_SECRET_PASS_123")

# The Shortener Domain
SHORTENER_DOMAIN = "nanolinks.in"

# Minimum time user must stay on the shortener (seconds)
MIN_TIME_SECONDS = 15 

# ================= DATABASE SETUP =================
client = AsyncIOMotorClient(MONGO_URI)
db = client["url_protector_db"]  # Database name
links_col = db["links"]          # Stores original URLs
sessions_col = db["sessions"]    # Stores temporary user sessions

async def init_db():
    # Create a TTL index so sessions expire automatically after 10 minutes (600 seconds)
    # This keeps the database clean.
    try:
        await sessions_col.create_index("created_at", expireAfterSeconds=600)
    except Exception as e:
        print(f"Index creation warning (safe to ignore if exists): {e}")

app = FastAPI(on_startup=[init_db])

# ================= MODELS =================
class GenerateRequest(BaseModel):
    url: str
    password: str

# ================= HELPER FUNCTION =================
def get_base_url(request: Request):
    """
    Automatically detects the domain of the app.
    Forces HTTPS for security if not on localhost.
    """
    url = str(request.base_url).rstrip("/")
    if "localhost" not in url and "127.0.0.1" not in url:
        url = url.replace("http://", "https://")
    return url

# ================= ROUTES =================

@app.get("/")
async def home():
    return HTMLResponse("""
    <html>
        <head><title>System Active</title></head>
        <body style="display:flex; justify-content:center; align-items:center; height:100vh; font-family:sans-serif;">
            <div style="text-align:center;">
                <h1 style="color:#2ecc71;">🚀 Anti-Bypass System is Online</h1>
                <p>MongoDB Connected.</p>
            </div>
        </body>
    </html>
    """)

# 1. ADMIN: Link Encrypt/Generate
# Send POST request here with JSON: {"url": "TARGET_URL", "password": "YOUR_PASS"}
@app.post("/api/generate")
async def generate_link(data: GenerateRequest, request: Request):
    if data.password != ADMIN_PASSWORD:
        raise HTTPException(status_code=403, detail="Wrong Password")
    
    # Auto-detect Base URL
    base_url = get_base_url(request)
    
    # Generate unique ID for the link
    link_id = secrets.token_urlsafe(6)
    
    await links_col.insert_one({
        "link_id": link_id,
        "original_url": data.url,
        "created_at": time.time()
    })
    
    # This URL goes into your Shortener
    start_url = f"{base_url}/s/{link_id}"
    
    return {
        "success": True,
        "original_url": data.url,
        "link_id": link_id,
        "start_url": start_url,
        "instruction": "Use 'start_url' in nanolinks.in"
    }

# 2. START PAGE: User clicks this -> Timer Starts -> Redirects to Shortener
@app.get("/s/{link_id}")
async def start_session(link_id: str, request: Request):
    # Check if link exists
    link_data = await links_col.find_one({"link_id": link_id})
    if not link_data:
        return HTMLResponse("<h1>❌ Invalid Link ID</h1>", status_code=404)

    # Auto-detect Base URL
    base_url = get_base_url(request)

    # Generate a secret token for this specific user session
    session_token = secrets.token_urlsafe(16)
    
    # STORE START TIME IN DB (This prevents bypassing)
    await sessions_col.insert_one({
        "token": session_token,
        "link_id": link_id,
        "start_time": time.time(),
        "created_at": time.time() # Used for auto-deletion
    })

    # The URL user returns to after shortener
    verify_dest = f"{base_url}/verify?token={session_token}"
    
    # Construct the Shortener URL (nanolinks format)
    # Encodes the verify URL inside the shortener URL
    final_shortener_url = f"https://{SHORTENER_DOMAIN}/?url={quote(verify_dest)}"

    # Display Loading/Redirect Page
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Securing Link...</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <meta http-equiv="refresh" content="1;url={final_shortener_url}">
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; text-align: center; padding: 20px; background: #f8f9fa; display: flex; flex-direction: column; justify-content: center; height: 90vh; }}
            .loader {{ border: 4px solid #f3f3f3; border-top: 4px solid #3498db; border-radius: 50%; width: 40px; height: 40px; animation: spin 1s linear infinite; margin: 20px auto; }}
            @keyframes spin {{ 0% {{ transform: rotate(0deg); }} 100% {{ transform: rotate(360deg); }} }}
            .card {{ background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); max-width: 400px; margin: auto; }}
        </style>
    </head>
    <body>
        <div class="card">
            <div class="loader"></div>
            <h3>Protection Initiated</h3>
            <p style="color: #666;">Redirecting to secure provider...</p>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(html_content)

# 3. VERIFY PAGE: User comes back here
@app.get("/verify")
async def verify_session(token: str = Query(...)):
    # 1. Find the session in DB
    session = await sessions_col.find_one({"token": token})
    
    if not session:
        return HTMLResponse("""
            <div style="font-family:sans-serif; text-align:center; margin-top:50px;">
                <h1 style="color:red;">🚫 Session Expired</h1>
                <p>Please start from the beginning.</p>
            </div>
        """, status_code=400)

    # 2. Calculate Time Spent
    time_spent = time.time() - session["start_time"]
    
    # 3. Validation Logic
    if time_spent < MIN_TIME_SECONDS:
        return HTMLResponse(f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <style>
                    body {{ font-family: sans-serif; text-align: center; padding: 20px; background: #fff0f0; }}
                    .box {{ background: white; padding: 20px; border-radius: 10px; border: 1px solid #ffcdd2; margin-top: 50px; }}
                    h2 {{ color: #c62828; }}
                </style>
            </head>
            <body>
                <div class="box">
                    <h2>🚫 Too Fast!</h2>
                    <p>You only spent <b>{int(time_spent)} seconds</b>.</p>
                    <p>Minimum required: <b>{MIN_TIME_SECONDS} seconds</b>.</p>
                    <hr>
                    <p><small>Go back and wait for the timer to complete.</small></p>
                </div>
            </body>
            </html>
        """, status_code=403)

    # 4. Get Original Link
    link_data = await links_col.find_one({"link_id": session["link_id"]})
    
    if not link_data:
        return HTMLResponse("<h1>❌ Link Broken</h1>", status_code=404)

    # 5. Security: Delete the token so it cannot be used again
    await sessions_col.delete_one({"_id": session["_id"]})

    # 6. Success Redirect
    return HTMLResponse(f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Success</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            body {{ font-family: sans-serif; text-align: center; padding: 20px; background: #e8f5e9; }}
            .box {{ background: white; padding: 40px; border-radius: 15px; max-width: 500px; margin: 50px auto; box-shadow: 0 4px 15px rgba(0,0,0,0.1); }}
            .btn {{ background: #2ecc71; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block; margin-top: 15px; }}
        </style>
        <script>
            // Automatic redirect backup
            setTimeout(() => {{
                window.location.href = "{link_data['original_url']}";
            }}, 2500);
        </script>
    </head>
    <body>
        <div class="box">
            <h1 style="color: #27ae60;">✅ Verified</h1>
            <p>You spent {int(time_spent)} seconds.</p>
            <p>Redirecting you to destination...</p>
            <div style="margin-top:20px;">
                <div style="width: 100%; background-color: #ddd; height: 5px; border-radius:5px;">
                  <div style="width: 0%; height: 100%; background-color: #27ae60; animation: progress 2.5s linear forwards;"></div>
                </div>
            </div>
            <br>
            <a href="{link_data['original_url']}" class="btn">Click here if not redirected</a>
        </div>
        <style>
            @keyframes progress {{ 0% {{ width: 0%; }} 100% {{ width: 100%; }} }}
        </style>
    </body>
    </html>
    """)
