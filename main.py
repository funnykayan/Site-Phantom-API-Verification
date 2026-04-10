from fastapi import FastAPI, Request, Query, HTTPException, Depends, Form
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import sqlite3
import secrets
import time
import os
import apikeys
import httpx
import re
import bcrypt
from dotenv import load_dotenv
from itsdangerous import URLSafeTimedSerializer, BadSignature
from typing import Optional

# Load .env
load_dotenv()

# ===== CONFIGURATION =====
BOT_SECRET = os.getenv("BOT_SECRET")
ROBLOX_ORIGIN = "https://www.roblox.com"  # ← FIXED: removed trailing spaces

ROBLOSECURITY = os.getenv("ROBLOSECURITY")

GROUP_ID = "14795663"
GAME_SECRET = os.getenv("GAME_SECRET")

# ===== DISCORD AUTH CONFIG =====
DISCORD_CLIENT_ID = os.getenv("DISCORD_CLIENT_ID")
DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET")
DISCORD_REDIRECT_URI = os.getenv("DISCORD_REDIRECT_URI")
SECRET_KEY = os.getenv("SECRET_KEY", "fallback-insecure-key-change-in-prod")

serializer = URLSafeTimedSerializer(SECRET_KEY, salt="session-signer")

# Initialize FastAPI
app = FastAPI()

# Serve static files from the `static` directory at `/static` URL path
app.mount("/static", StaticFiles(directory="static"), name="static")

# Rate limiter
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=[ROBLOX_ORIGIN],
    allow_methods=["GET"],
    allow_headers=["*"],
)

# ===== DATABASE INITIALIZATION =====
def init_db():
    conn = sqlite3.connect("verify.db")
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS pending (
            code TEXT PRIMARY KEY,
            discord_id INTEGER NOT NULL,
            created_at REAL NOT NULL
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS verified (
            discord_id INTEGER PRIMARY KEY,
            roblox_id INTEGER NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def init_accounts_db():
    conn = sqlite3.connect("accounts.db")
    c = conn.cursor()
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='accounts'")
    if not c.fetchone():
        c.execute("""
            CREATE TABLE accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE,
                password_hash TEXT NOT NULL,
                discord_id TEXT UNIQUE,
                roblox_id INTEGER UNIQUE,
                created_at REAL NOT NULL
            )
        """)
        conn.commit()
        conn.close()
        return

    c.execute("PRAGMA table_info(accounts)")
    cols = c.fetchall()
    email_col = None
    for col in cols:
        if col[1] == 'email':
            email_col = col
            break

    if email_col and email_col[3] == 1:
        c.execute("BEGIN TRANSACTION")
        c.execute("""
            CREATE TABLE IF NOT EXISTS accounts_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE,
                password_hash TEXT NOT NULL,
                discord_id TEXT UNIQUE,
                roblox_id INTEGER UNIQUE,
                created_at REAL NOT NULL
            )
        """)
        c.execute("INSERT OR IGNORE INTO accounts_new (id, username, email, password_hash, discord_id, roblox_id, created_at) SELECT id, username, email, password_hash, discord_id, roblox_id, created_at FROM accounts")
        c.execute("DROP TABLE accounts")
        c.execute("ALTER TABLE accounts_new RENAME TO accounts")
        conn.commit()

    conn.close()

def init_oauth_db():
    conn = sqlite3.connect("accounts.db")
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS oauth_apps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id TEXT UNIQUE NOT NULL,
            client_secret TEXT NOT NULL,
            name TEXT NOT NULL,
            redirect_uri TEXT NOT NULL,
            owner_account_id INTEGER NOT NULL,
            created_at REAL NOT NULL,
            FOREIGN KEY (owner_account_id) REFERENCES accounts(id)
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS oauth_codes (
            code TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            account_id INTEGER NOT NULL,
            redirect_uri TEXT NOT NULL,
            scope TEXT NOT NULL DEFAULT 'identify',
            created_at REAL NOT NULL
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS oauth_tokens (
            access_token TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            account_id INTEGER NOT NULL,
            scope TEXT NOT NULL DEFAULT 'identify',
            created_at REAL NOT NULL,
            expires_at REAL NOT NULL
        )
    """)
    conn.commit()
    conn.close()

init_db()
init_accounts_db()
init_oauth_db()

# ===== SESSION HELPERS =====
def change_user_rank(group_id, user_id, role_id):
    # Use a requests Session to persist the .ROBLOSECURITY cookie and retrieve CSRF token
    s = requests.Session()
    if not ROBLOSECURITY:
        raise RuntimeError("ROBLOSECURITY not configured")
    s.cookies.set('.ROBLOSECURITY', ROBLOSECURITY)

    # Fetch CSRF token (Roblox requires an X-CSRF-TOKEN for state-changing requests)
    csrf_resp = s.post("https://auth.roblox.com/v2/logout")
    csrf_token = csrf_resp.headers.get("x-csrf-token")
    if not csrf_token:
        # Try once more
        csrf_resp = s.post("https://auth.roblox.com/v2/logout")
        csrf_token = csrf_resp.headers.get("x-csrf-token")

    headers = {
        "X-CSRF-TOKEN": csrf_token or "",
        "Content-Type": "application/json"
    }

    # Use PATCH (not POST) to change a user's role in a group
    resp = s.patch(
        f"https://groups.roblox.com/v1/groups/{group_id}/users/{user_id}",
        headers=headers,
        json={"roleId": role_id},
        timeout=15
    )

    try:
        return {"status_code": resp.status_code, "body": resp.json()}
    except Exception:
        return {"status_code": resp.status_code, "text": resp.text}


def get_current_session(request: Request):
    session_cookie = request.cookies.get("session")
    if not session_cookie:
        return None
    try:
        return serializer.loads(session_cookie, max_age=86400)
    except BadSignature:
        return None

def require_auth(request: Request):
    session = get_current_session(request)
    if not session:
        raise HTTPException(status_code=307, detail="Redirect to login", headers={"Location": "/account/login"})
    return session


def render_template_with_topbar(request: Request, file_name: str) -> HTMLResponse:
    file_path = os.path.join("static", file_name)
    if not os.path.exists(file_path):
        raise HTTPException(500, "Template missing")

    with open(file_path, "r", encoding="utf-8") as f:
        html = f.read()

    session = get_current_session(request)
    username = None
    if session and isinstance(session, dict):
        username = session.get("username")

    if username:
        username_html = f"<div class=\"top-user\">Signed in as <strong>{username}</strong> · <a href=\"/account/logout\">Logout</a></div>"
    else:
        username_html = '<div class="top-user"><a href="/account/login">Login</a> · <a href="/account/create">Create Account</a></div>'

    html = html.replace("{{ topbar_account }}", username_html)
    return HTMLResponse(html)

# ===== ACCOUNT ROUTES =====
@app.get("/privacy")
@limiter.limit("10/minute")
async def privacy_policy(request: Request):
    return render_template_with_topbar(request, "privacy.html")

@app.get("/terms")
@limiter.limit("10/minute")
async def terms_of_service(request: Request):
    return render_template_with_topbar(request, "terms.html")

@app.get("/account/create")
@limiter.limit("10/minute")
async def show_create_account(request: Request):
    return render_template_with_topbar(request, "account_create.html")

@app.post("/account/create")
@limiter.limit("3/minute")
async def create_account(
    request: Request,
    username: str = Form(..., min_length=3, max_length=20),
    email: Optional[str] = Form(None),
    password: str = Form(..., min_length=8)
):
    if email:
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            raise HTTPException(400, "Invalid email")
    if not re.match(r"^[a-zA-Z0-9_]+$", username):
        raise HTTPException(400, "Username can only contain letters, numbers, and underscores")

    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    conn = sqlite3.connect("accounts.db")
    c = conn.cursor()
    try:
        c.execute("""
            INSERT INTO accounts (username, email, password_hash, created_at)
            VALUES (?, ?, ?, ?)
        """, (username, email, password_hash, time.time()))
        conn.commit()
    except sqlite3.IntegrityError as e:
        conn.close()
        err = str(e).lower()
        if "username" in err:
            raise HTTPException(400, "Username already taken")
        elif "email" in err:
            raise HTTPException(400, "Email already registered")
        else:
            raise HTTPException(500, "Registration failed")
    finally:
        conn.close()

    return RedirectResponse(url="/account/login", status_code=303)

@app.get("/account/login")
@limiter.limit("10/minute")
async def show_login(request: Request, next: Optional[str] = Query(None)):
    file_path = os.path.join("static", "account_login.html")
    if not os.path.exists(file_path):
        raise HTTPException(500, "Template missing")
    with open(file_path, "r", encoding="utf-8") as f:
        html = f.read()

    # Inject hidden 'next' field into the login form
    next_field = f'<input type="hidden" name="next" value="{next}">' if next else ''
    html = html.replace('{{ next_field }}', next_field)

    session = get_current_session(request)
    username = None
    if session and isinstance(session, dict):
        username = session.get("username")
    if username:
        username_html = f'<div class="top-user">Signed in as <strong>{username}</strong> · <a href="/account/logout">Logout</a></div>'
    else:
        username_html = '<div class="top-user"><a href="/account/login">Login</a> · <a href="/account/create">Create Account</a></div>'
    html = html.replace('{{ topbar_account }}', username_html)

    return HTMLResponse(html)

@app.post("/account/login")
@limiter.limit("5/minute")
async def login_account(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    next: Optional[str] = Form(None),
):
    conn = sqlite3.connect("accounts.db")
    c = conn.cursor()
    c.execute("SELECT id, username, password_hash FROM accounts WHERE username = ? OR email = ?", (username, username))
    row = c.fetchone()
    conn.close()

    if not row or not bcrypt.checkpw(password.encode('utf-8'), row[2].encode('utf-8')):
        raise HTTPException(401, "Invalid credentials")

    account_id, username_db, _ = row
    session_payload = serializer.dumps({"account_id": account_id, "username": username_db})

    # Redirect to 'next' URL if provided (e.g. OAuth authorize), otherwise dashboard
    redirect_to = next if next and next.startswith("/") else "/userdash"
    response = RedirectResponse(url=redirect_to, status_code=303)
    response.set_cookie(
        key="session",
        value=session_payload,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=86400,
    )
    return response

@app.get("/account/logout")
@limiter.limit("10/minute")
async def logout_account(request: Request):
    response = RedirectResponse(url="/")
    response.delete_cookie("session")
    return response

# ===== COMMON HEADERS FOR EXTERNAL CALLS =====
COMMON_HEADERS = {
    "User-Agent": "SitePhantom/1.0 (+https://verify.deltadb.site)"
}

# ===== DISCORD AUTH =====
@app.get("/auth/discord")
@limiter.limit("5/minute")
async def login_discord(request: Request):
    if not DISCORD_CLIENT_ID or not DISCORD_REDIRECT_URI:
        raise HTTPException(500, "Discord OAuth not configured")
    url = (
        "https://discord.com/api/oauth2/authorize?"  # ← FIXED: no trailing space
        f"client_id={DISCORD_CLIENT_ID}&"
        f"redirect_uri={DISCORD_REDIRECT_URI}&"
        "response_type=code&scope=identify"
    )
    return RedirectResponse(url)

@app.get("/auth/discord/callback")
@limiter.limit("5/minute")
async def discord_callback(request: Request, code: str):
    if not DISCORD_CLIENT_ID or not DISCORD_CLIENT_SECRET or not DISCORD_REDIRECT_URI:
        raise HTTPException(500, "Discord OAuth not configured")

    async with httpx.AsyncClient() as client:
        token_resp = await client.post(
            "https://discord.com/api/oauth2/token",  # ← FIXED
            data={
                "client_id": DISCORD_CLIENT_ID,
                "client_secret": DISCORD_CLIENT_SECRET,
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": DISCORD_REDIRECT_URI,
                "scope": "identify",
            },
            headers={"Content-Type": "application/x-www-form-urlencoded", **COMMON_HEADERS},
        )
        if token_resp.status_code != 200:
            raise HTTPException(400, "Failed to get Discord token")

        access_token = token_resp.json()["access_token"]
        user_resp = await client.get(
            "https://discord.com/api/users/@me",  # ← FIXED
            headers={"Authorization": f"Bearer {access_token}", **COMMON_HEADERS},
        )
        if user_resp.status_code != 200:
            raise HTTPException(400, "Failed to fetch Discord user")

        user_data = user_resp.json()
        discord_id = user_data["id"]
        discord_username = f"{user_data['username']}#{user_data['discriminator']}"

        current_session = get_current_session(request)
        if current_session and "account_id" in current_session:
            conn = sqlite3.connect("accounts.db")
            c = conn.cursor()
            try:
                c.execute("UPDATE accounts SET discord_id = ? WHERE id = ?", (discord_id, current_session["account_id"]))
                conn.commit()
            except sqlite3.IntegrityError:
                pass
            conn.close()
            return RedirectResponse(url="/userdash")

        else:
            session_payload = serializer.dumps({
                "id": discord_id,
                "username": discord_username
            })
            response = RedirectResponse(url="/userdash")
            response.set_cookie(
                key="session",
                value=session_payload,
                httponly=True,
                secure=True,
                samesite="lax",
                max_age=86400,
            )
            return response

# ===== ROBLOX OAUTH =====
ROBLOX_CLIENT_ID = os.getenv("ROBLOX_CLIENT_ID")
ROBLOX_CLIENT_SECRET = os.getenv("ROBLOX_CLIENT_SECRET")
ROBLOX_REDIRECT_URI = os.getenv("ROBLOX_REDIRECT_URI")

@app.get("/auth/roblox")
@limiter.limit("5/minute")
async def login_roblox(request: Request, session: dict = Depends(require_auth)):
    if not ROBLOX_CLIENT_ID or not ROBLOX_REDIRECT_URI:
        raise HTTPException(500, "Roblox OAuth not configured")
    
    url = (
        "https://apis.roblox.com/oauth/v1/authorize?"  # ← FIXED
        f"client_id={ROBLOX_CLIENT_ID}&"
        f"redirect_uri={ROBLOX_REDIRECT_URI}&"
        "response_type=code&"
        "scope=openid"
    )
    return RedirectResponse(url)

import ssl
import certifi

# Create an SSL context that uses system certificates
ssl_context = ssl.create_default_context()
ssl_context.load_verify_locations(certifi.where())

import requests
import base64
import json

@app.get("/auth/roblox/callback")
@limiter.limit("5/minute")
async def roblox_callback(request: Request, code: str):
    if not ROBLOX_CLIENT_ID or not ROBLOX_CLIENT_SECRET or not ROBLOX_REDIRECT_URI:
        raise HTTPException(500, "Roblox OAuth not configured")

    session_data = get_current_session(request)
    if not session_data:
        return RedirectResponse("/account/login")

    try:
        token_resp = requests.post(
            "https://apis.roblox.com/oauth/v1/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": ROBLOX_REDIRECT_URI,
            },
            auth=(ROBLOX_CLIENT_ID, ROBLOX_CLIENT_SECRET),
            headers={
                "User-Agent": "Mozilla/5.0",
                "Connection": "close"
            },
            timeout=20,
        )

        if token_resp.status_code != 200:
            print("ROBLOX TOKEN ERROR:", token_resp.text)
            raise HTTPException(400, "Token exchange failed")

        tokens = token_resp.json()
        id_token = tokens.get("id_token")
        if not id_token:
            raise HTTPException(400, "No ID token received")

        payload = id_token.split('.')[1]
        payload += "=" * (-len(payload) % 4)
        decoded = base64.urlsafe_b64decode(payload).decode("utf-8")
        claims = json.loads(decoded)

        roblox_id = claims.get("sub")
        if not roblox_id:
            raise HTTPException(400, "Roblox ID missing")

        # Save Roblox ID
        if "account_id" in session_data:
            conn = sqlite3.connect("accounts.db")
            c = conn.cursor()
            try:
                c.execute(
                    "UPDATE accounts SET roblox_id = ? WHERE id = ?",
                    (roblox_id, session_data["account_id"])
                )
                conn.commit()
            except sqlite3.IntegrityError:
                pass
            finally:
                conn.close()

        response = RedirectResponse("/userdash")
        response.set_cookie(
            key="session",
            value=serializer.dumps(session_data),
            httponly=True,
            secure=True,
            samesite="lax",
            max_age=86400,
        )
        return response

    except requests.exceptions.RequestException as e:
        print("ROBLOX REQUEST ERROR:", repr(e))
        raise HTTPException(502, "Roblox connection failed")

    except Exception:
        import traceback
        traceback.print_exc()
        raise HTTPException(500, "Verification failed")


# ===== USER DASHBOARD =====
import json
import requests

def get_user_rank_in_group(roblox_id: int, group_id: int):
    """Fetch user's role in a specific Roblox group using the public API."""
    try:
        resp = requests.get(
            f"https://groups.roblox.com/v2/users/{roblox_id}/groups/roles",
            timeout=10
        )
        if resp.status_code != 200:
            return None
        data = resp.json()
        for entry in data["data"]:
            if entry["group"]["id"] == group_id:
                return {
                    "role_name": entry["role"]["name"],
                    "rank": entry["role"]["rank"]
                }
        return None
    except Exception as e:
        print(f"Error fetching rank for Roblox ID {roblox_id} in group {group_id}: {e}")
        return None

@app.get("/userdash", response_class=HTMLResponse)
@limiter.limit("20/minute")
async def user_dashboard(request: Request, session: dict = Depends(require_auth)):
    account_id = session.get("account_id")
    discord_id = None
    roblox_id = None
    username_display = session.get("username", "Unknown")
    email_display = "N/A"

    if account_id:
        conn = sqlite3.connect("accounts.db")
        c = conn.cursor()
        c.execute("SELECT email, discord_id, roblox_id FROM accounts WHERE id = ?", (account_id,))
        row = c.fetchone()
        conn.close()
        if not row:
            return RedirectResponse("/account/logout")
        email_val, stored_discord_id, stored_roblox_id = row
        email_display = email_val if email_val else "N/A"
        discord_id = stored_discord_id
        roblox_id = stored_roblox_id

    elif "id" in session:
        discord_id = session["id"]
        conn = sqlite3.connect("accounts.db")
        c = conn.cursor()
        c.execute("SELECT roblox_id FROM accounts WHERE discord_id = ?", (discord_id,))
        row = c.fetchone()
        conn.close()
        if row:
            roblox_id = row[0]

    # Load groups configuration
    try:
        with open("data/groups.json", "r") as f:
            groups_config = json.load(f)
    except Exception as e:
        print(f"Failed to load groups.json: {e}")
        groups_config = {}

    # Flatten all groups into a list
    all_groups = []
    for key, group_list in groups_config.items():
        all_groups.extend(group_list)

    # Determine if user is a "guest" (not verified on Roblox)
    is_guest = (roblox_id is None)

    main_group_row = ""
    extra_groups_items = []
    show_groups_button = False

    # Only check group membership if user is verified
    if roblox_id:
        for group in all_groups:
            group_id = group["id"]
            group_name = group["name"]
            location = group.get("location", "")
            show_if_guest = group.get("showIfGuest", True)

            # Skip if showIfGuest=False and user is guest — but user isn't guest here
            # So we only skip if user is NOT in the group
            rank_info = get_user_rank_in_group(roblox_id, group_id)
            if not rank_info:
                continue

            role_display = f"{rank_info['role_name']}"

            if location == "userdash":
                main_group_row = f'<div class="info-row"><span class="info-label">{group_name}</span><span class="info-value">{role_display}</span></div>'
            elif location == "userdash/groupslist":
                # Respect showIfGuest: if false, still show to verified users
                # (since they're not guests)
                extra_groups_items.append(
                    f'<div class="group-item"><span class="group-name">{group_name}</span><span class="group-rank">{role_display}</span></div>'
                )
                show_groups_button = True

    # Build prompts
    prompts = []
    if not discord_id:
        prompts.append(
            '<div class="card">'
            '<h2>Link Discord</h2>'
            '<p>Link your Discord account for full access to all features.</p>'
            '<div class="actions" style="justify-content: flex-start;">'
            '<a href="/auth/discord" class="btn btn-primary">Link Discord</a>'
            '</div>'
            '</div>'
        )

    if not roblox_id:
        prompts.append(
            '<div class="card">'
            '<h2>Verify Roblox</h2>'
            '<p>Verify your Roblox account to access in-game systems.</p>'
            '<div class="actions" style="justify-content: flex-start;">'
            '<a href="/auth/roblox" class="btn btn-primary">Verify on Roblox</a>'
            '</div>'
            '</div>'
        )

    prompts_html = "\n".join(prompts) if prompts else (
        '<div class="card">'
        '<h2>Fully Verified</h2>'
        '<p>All systems accessible. You are good to go!</p>'
        '</div>'
    )

    # Load HTML template
    file_path = os.path.join("static", "userdash.html")
    if not os.path.exists(file_path):
        raise HTTPException(500, "Dashboard template missing")

    with open(file_path, "r", encoding="utf-8") as f:
        html = f.read()

    # Inject dynamic content
    html = html.replace("{{ username }}", username_display)
    html = html.replace("{{ email }}", email_display)
    html = html.replace("{{ discord_status }}", "Linked" if discord_id else "Not linked")
    html = html.replace("{{ roblox_status }}", str(roblox_id) if roblox_id else "Not verified")
    html = html.replace("{{ main_group_row }}", main_group_row)
    html = html.replace("{{ prompts_section }}", prompts_html)

    # Groups button and modal content
    groups_button = '<button class="btn btn-secondary" onclick="openModal()">View Departments</button>' if show_groups_button else ""
    groups_list_items = "\n".join(extra_groups_items)
    html = html.replace("{{ groups_button }}", groups_button)
    html = html.replace("{{ groups_list_items }}", groups_list_items)

    # Inject topbar
    username_for_top = session.get("username") if session and isinstance(session, dict) else None
    if username_for_top:
        username_html = f"<div class=\"top-user\">Signed in as <strong>{username_for_top}</strong> · <a href=\"/account/logout\">Logout</a></div>"
    else:
        username_html = '<div class="top-user"><a href="/account/login">Login</a> · <a href="/account/create">Create Account</a></div>'
    html = html.replace("{{ topbar_account }}", username_html)

    return HTMLResponse(html)

# ===== EXISTING ROUTES — UNCHANGED =====
@app.get("/accounts/admin", response_class=HTMLResponse)
@limiter.limit("10/minute")
async def accounts_admin(request: Request, session: dict = Depends(require_auth)):
    conn = sqlite3.connect("accounts.db")
    c = conn.cursor()
    c.execute("SELECT id, username, email, created_at, discord_id, roblox_id FROM accounts ORDER BY created_at DESC")
    rows = c.fetchall()
    conn.close()

    file_path = os.path.join("static", "admin_list.html")
    if not os.path.exists(file_path):
        raise HTTPException(500, "Admin list template missing")

    with open(file_path, "r", encoding="utf-8") as f:
        html = f.read()

    rows_html = ""
    for r in rows:
        id_, username, email, created_at, discord_id, roblox_id = r
        created_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(created_at))
        rows_html += (
            f"<tr>"
            f"<td>{id_}</td>"
            f"<td><a href=\"/accounts/admin/{id_}\">{username}</a></td>"
            f"<td>{email or ''}</td>"
            f"<td>{discord_id or ''}</td>"
            f"<td>{roblox_id or ''}</td>"
            f"<td>{created_str}</td>"
            f"</tr>"
        )

    html = html.replace("{{ accounts_rows }}", rows_html)
    # inject topbar
    username = session.get("username") if session and isinstance(session, dict) else None
    if username:
        username_html = f"<div class=\"top-user\">Signed in as <strong>{username}</strong> · <a href=\"/account/logout\">Logout</a></div>"
    else:
        username_html = '<div class="top-user"><a href="/account/login">Login</a> · <a href="/account/create">Create Account</a></div>'
    html = html.replace("{{ topbar_account }}", username_html)
    return HTMLResponse(html)

@app.get("/accounts/admin/{account_id}", response_class=HTMLResponse)
@limiter.limit("10/minute")
async def accounts_admin_view(request: Request, account_id: int, session: dict = Depends(require_auth)):
    conn = sqlite3.connect("accounts.db")
    c = conn.cursor()
    c.execute("SELECT id, username, email, created_at, discord_id, roblox_id FROM accounts WHERE id = ?", (account_id,))
    row = c.fetchone()
    conn.close()

    if not row:
        raise HTTPException(404, "Account not found")

    id_, username, email, created_at, discord_id, roblox_id = row

    file_path = os.path.join("static", "admin_view.html")
    if not os.path.exists(file_path):
        raise HTTPException(500, "Admin view template missing")

    with open(file_path, "r", encoding="utf-8") as f:
        html = f.read()

    html = html.replace("{{ id }}", str(id_))
    html = html.replace("{{ username }}", username)
    html = html.replace("{{ email }}", str(email) if email else "N/A")
    html = html.replace("{{ discord_id }}", str(discord_id) if discord_id else "N/A")
    html = html.replace("{{ roblox_id }}", str(roblox_id) if roblox_id else "N/A")
    html = html.replace("{{ created_at }}", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(created_at)))

    # inject topbar
    username = session.get("username") if session and isinstance(session, dict) else None
    if username:
        username_html = f"<div class=\"top-user\">Signed in as <strong>{username}</strong> · <a href=\"/account/logout\">Logout</a></div>"
    else:
        username_html = '<div class="top-user"><a href="/account/login">Login</a> · <a href="/account/create">Create Account</a></div>'
    html = html.replace("{{ topbar_account }}", username_html)

    return HTMLResponse(html)

@app.get("/api/private/info/{userid}/{secret}")
@limiter.limit("10/minute")  # Prevent abuse
async def get_user_info_api(
    request: Request,
    userid: int,
    secret: str
):
    # Validate secret
    if secret != BOT_SECRET:
        raise HTTPException(status_code=403, detail="Invalid secret")

    # Fetch account by Roblox ID or Discord ID
    conn = sqlite3.connect("accounts.db")
    c = conn.cursor()
    
    # Try Roblox ID first
    c.execute("SELECT id, username, email, discord_id, roblox_id FROM accounts WHERE roblox_id = ?", (userid,))
    row = c.fetchone()
    
    # If not found, try Discord ID
    if not row:
        c.execute("SELECT id, username, email, discord_id, roblox_id FROM accounts WHERE discord_id = ?", (str(userid),))
        row = c.fetchone()
    
    conn.close()

    if not row:
        return {
            "found": False,
            "error": "User not found in system"
        }

    account_id, username, email, discord_id, roblox_id = row

    # Only return verified data
    if not roblox_id or not discord_id:
        return {
            "found": True,
            "verified": False,
            "username": username,
            "discord_id": discord_id,
            "roblox_id": roblox_id,
            "departments": []
        }

    # Load groups config
    try:
        with open("data/groups.json", "r") as f:
            groups_config = json.load(f)
    except Exception as e:
        print(f"Failed to load groups.json: {e}")
        groups_config = {}

    all_groups = []
    for key, group_list in groups_config.items():
        all_groups.extend(group_list)

    departments = []

    # Fetch rank in each group
    for group in all_groups:
        group_id = group["id"]
        show_if_guest = group.get("showIfGuest", True)
        location = group.get("location", "")

        # Skip if showIfGuest=False — but since user is verified, we still check
        rank_info = get_user_rank_in_group(roblox_id, group_id)
        if rank_info:
            departments.append({
                "group_id": group_id,
                "name": group["name"],
                "role_name": rank_info["role_name"],
                "rank": rank_info["rank"],
                "location": location
            })

    return {
        "found": True,
        "verified": True,
        "username": username,
        "email": email,
        "discord_id": discord_id,
        "roblox_id": roblox_id,
        "departments": departments
    }


@app.get("/api/private/changerank/{groupid}/{userid}/{roleid}/{secret}")
@limiter.limit("10/minute")
async def api_change_rank(
    request: Request,
    groupid: int,
    userid: int,
    roleid: int,
    secret: str
):
    # Validate secret
    if secret != BOT_SECRET:
        raise HTTPException(status_code=403, detail="Invalid secret")

    try:
        result = change_user_rank(groupid, userid, roleid)
        return {"status": "success", "result": result}
    except Exception as e:
        print("change_user_rank error:", e)
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/generate")
@limiter.limit("5/minute")
async def generate_code(
    request: Request,
    discord_id: int = Query(..., gt=0),
    secret: str = Query(...)
):
    if secret != BOT_SECRET:
        raise HTTPException(status_code=403, detail="Forbidden")
    code = str(secrets.randbelow(10000)).zfill(4)
    now = time.time()
    conn = sqlite3.connect("verify.db")
    c = conn.cursor()
    c.execute("DELETE FROM pending WHERE created_at < ?", (now - 600,))
    try:
        c.execute("INSERT INTO pending (code, discord_id, created_at) VALUES (?, ?, ?)",
                  (code, discord_id, now))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return await generate_code(request, discord_id, secret)
    conn.close()
    return {"code": code}

@app.get("/submit")
@limiter.limit("3/minute")
async def submit_code(
    request: Request,
    code: str = Query(..., min_length=4, max_length=4),
    roblox_id: int = Query(..., gt=0)
):
    conn = sqlite3.connect("verify.db")
    c = conn.cursor()
    c.execute("SELECT discord_id FROM pending WHERE code = ?", (code,))
    row = c.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=400, detail="Invalid or expired code")
    
    discord_id = row[0]
    c.execute("INSERT OR REPLACE INTO verified (discord_id, roblox_id) VALUES (?, ?)",
              (discord_id, roblox_id))
    c.execute("DELETE FROM pending WHERE code = ?", (code,))
    conn.commit()
    conn.close()
    return {"status": "success"}

@app.get("/dash")
async def dashboard(request: Request):
    return render_template_with_topbar(request, "dashboard.html")

@app.get("/", response_class=HTMLResponse)
@limiter.limit("30/minute")
async def landing(request: Request):
    file_path = os.path.join("static", "index.html")
    if not os.path.exists(file_path):
        raise HTTPException(500, "Index template missing")

    with open(file_path, "r", encoding="utf-8") as f:
        html = f.read()

    session = get_current_session(request)
    username = None
    if session and isinstance(session, dict):
        username = session.get("username")

    if username:
        username_html = f"<div class=\"top-user\">Signed in as <strong>{username}</strong> · <a href=\"/account/logout\">Logout</a></div>"
    else:
        username_html = '<div class="top-user"><a href="/account/login">Login</a> · <a href="/account/create">Create Account</a></div>'

    html = html.replace("{{ topbar_account }}", username_html)
    return HTMLResponse(html)

@app.get("/public")
async def public_page(request: Request):
    return render_template_with_topbar(request, "publicdevelopment.html")

@app.get("/public/verification-database")
@limiter.limit("5/minute")
async def public_verification_database(
    request: Request,
    apikey: str = Query(...)
):
    if apikey not in apikeys.apikeys:
        raise HTTPException(status_code=403, detail="Invalid API key")
    
    file_path = os.path.join("data", "verified_users.json")
    if not os.path.isfile(file_path):
        raise HTTPException(status_code=404, detail="Database not found")
    
    return FileResponse(file_path)

@app.get("/check")
def check_code(code: str = Query(..., min_length=4, max_length=4)):
    conn = sqlite3.connect("verify.db")
    c = conn.cursor()
    c.execute("SELECT discord_id FROM pending WHERE code = ?", (code,))
    row = c.fetchone()
    conn.close()
    if row:
        return {"valid": True, "discord_id": str(row[0])}
    return {"valid": False}


@app.get("/api/verificationcheck/{robloxid}")
@limiter.limit("10/minute")
async def verification_check(request: Request, robloxid: int):
    try:
        conn = sqlite3.connect("accounts.db")
        c = conn.cursor()
        c.execute("SELECT username, discord_id FROM accounts WHERE roblox_id = ?", (robloxid,))
        row = c.fetchone()
        conn.close()
    except Exception as e:
        print("DB error in verificationcheck:", e)
        raise HTTPException(status_code=500, detail="Database error")

    if row:
        username, discord_id = row
        return {"IsVerified": True, "discordId": str(discord_id) if discord_id else None, "username": username}

    return False


@app.get("/api/groupcheck/{account_id}")
@limiter.limit("10/minute")
async def group_check(request: Request, account_id: int):
    """Check which groups from groups.json a SitePhantom account's linked Roblox user belongs to."""
    # Look up the account's linked Roblox ID
    conn = sqlite3.connect("accounts.db")
    c = conn.cursor()
    c.execute("SELECT roblox_id FROM accounts WHERE id = ?", (account_id,))
    row = c.fetchone()
    conn.close()

    if not row:
        return {"error": "Account not found", "account_id": account_id, "roblox_linked": False, "groups": None}

    roblox_id = row[0]
    if not roblox_id:
        return {"account_id": account_id, "roblox_linked": False, "roblox_id": None, "groups": None}

    # Load groups config
    try:
        with open("data/groups.json", "r") as f:
            groups_config = json.load(f)
    except Exception as e:
        print(f"Failed to load groups.json: {e}")
        raise HTTPException(status_code=500, detail="Failed to load groups config")

    # Flatten all groups
    all_groups = []
    for key, group_list in groups_config.items():
        all_groups.extend(group_list)

    # Fetch all of the user's group roles in one call
    try:
        resp = requests.get(
            f"https://groups.roblox.com/v2/users/{roblox_id}/groups/roles",
            timeout=10
        )
        if resp.status_code != 200:
            raise HTTPException(status_code=502, detail="Failed to fetch Roblox group data")
        user_groups_data = resp.json().get("data", [])
    except requests.exceptions.RequestException as e:
        print(f"Roblox API error for groupcheck: {e}")
        raise HTTPException(status_code=502, detail="Roblox API request failed")

    # Build a lookup: group_id -> role info
    user_group_map = {}
    for entry in user_groups_data:
        user_group_map[entry["group"]["id"]] = entry["role"]

    # Check each configured group
    results = []
    for group in all_groups:
        group_id = group["id"]
        group_name = group["name"]
        role = user_group_map.get(group_id)

        results.append({
            "group_id": group_id,
            "name": group_name,
            "in_group": role is not None,
            "role_id": role["id"] if role else None,
            "role_name": role["name"] if role else None,
            "rank": role["rank"] if role else None,
        })

    return {"account_id": account_id, "roblox_linked": True, "roblox_id": roblox_id, "groups": results}


@app.post("/promote")
async def promote_user(
    request: Request,
    userid: int = Query(..., gt=0),
    roleid: int = Query(...)
):
    auth = request.headers.get("Authorization")
    if auth != f"Bearer {GAME_SECRET}":
        raise HTTPException(status_code=403, detail="Forbidden")

    GROUP_ID = "14795663"
    FULL_COOKIE = "rbx-ip2=1; GuestData=UserID=-488074393; RBXPaymentsFlowContext=582175cd-35be-43ba-926e-de3591e0c669,; .ROBLOSECURITY=_|WARNING:-DO-NOT-SHARE-THIS.--Sharing-this-will-allow-someone-to-log-in-as-you-and-to-steal-your-ROBUX-and-items.|_CAEaAhADIhsKBGR1aWQSEzE0NzY4MDc2NzM1OTE1Mjk5NTkoAw.hzig99dVYgHdIkXbS9ZIbTbiqLew5MOImVPj_mTrVgYhMsuRHA3ocDLdiNwpbZKbasB3EspT_NBDXK9NcVTr6buhKP-UavYbjFBF11vJogLtVTuG0k1evrchMFx77vniu5rgRNCJ_OBIxKGDz8hSHpJ9Bzzb9HBVL2D_Y860y2jW7HEGH-_tQLHpG-i8o74NRaPt_6RyvOyDtRbhU80lMX3jzN1X3NN8izmo0VMp68wQkM2Qz88ew7-2B3HbXctm5oMlz2Kzg7VHK6PUzjZFhsw-ahDKHA3XgbBhiVG5vc28aMSAxl9Uyrck5NU405fv7_2mVz5pN8silFAXomdxmTZcAJAG2v4Xl3vLmsdM0vFz6GSqE8_izmiozNcfXVWWSoeIXWk5JIvYSV5mMjRGq8jiFBKCLUD1iJDFcOQLMv9AKoxePFd98vk5OydAa2acTx8Cir1MHNM2l6GjfxdGENfyQ0FrrY8FvMES88CJ3Ng-n7Y6pRiSrU3qujrWzlhg2IApia23FVivoIgQsqq7d4diua9JLiCMHIXA_GXN6kXXCd7zkYKbPHNEhg4fOqubA7PcqkOQ0Y8wAw28BmcHYvWXFf1VTi7cdRymNFa70fJyjJNTU4KXDOo5X9StxgfCpOIn2L3neKD9HHU32gBmOBT_l-jcwEp1ZEG59jghEYbEXx9rOc6e1C34YOkc-fDoLODkF0lbHKgFMaf8fZDqGZ0o4uvdfsa1Q2Q2sgTRVwa-oUuUwi9iAJ_sVQ9as1hbZcra0XuV_WgqmcGXAtRYi0tF47hpACAut2M9nV3igyP7pB3p; RBXSessionTracker=sessionid=05d10b9d-ed46-4df1-a561-7581047b917d; RBXEventTrackerV2=CreateDate=01/31/2026 04:39:34&rbxid=10346796430&browserid=1769855962120001; RBXcb=RBXViralAcquisition=false&RBXSource=false&GoogleAnalytics=false"

    async with httpx.AsyncClient(timeout=15.0) as client:
        try:
            resp = await client.post(
                "https://auth.roblox.com/v2/logout",
                headers={"Cookie": FULL_COOKIE}
            )
            csrf = resp.headers.get("x-csrf-token")
            
            if not csrf:
                print(f"NO CSRF - Status: {resp.status_code}, Headers: {dict(resp.headers)}")
                raise HTTPException(status_code=500, detail="No CSRF token received")

            resp = await client.patch(
                f"https://groups.roblox.com/v1/groups/{GROUP_ID}/users/{userid}",
                headers={
                    "Cookie": FULL_COOKIE,
                    "X-CSRF-TOKEN": csrf,
                    "Content-Type": "application/json"
                },
                json={"roleId": roleid}
            )
            
            print(f"Promote response: {resp.status_code} - {resp.text}")
            
            if resp.status_code == 200:
                return {"status": "success"}
            else:
                raise HTTPException(status_code=resp.status_code, detail=f"Roblox API: {resp.text}")
                
        except Exception as e:
            print(f"ERROR: {str(e)}")
            raise HTTPException(status_code=500, detail=str(e))


# ===== DEVELOPER PORTAL & "LOGIN WITH SITEPHANTOM" OAUTH2 =====
from urllib.parse import urlparse

def _get_base_url(request: Request) -> str:
    """Derive the public base URL from the incoming request."""
    scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("x-forwarded-host", request.url.netloc)
    return f"{scheme}://{host}"


# --- Developer Portal ---
@app.get("/developer/apps", response_class=HTMLResponse)
@limiter.limit("20/minute")
async def developer_apps_page(request: Request, session: dict = Depends(require_auth)):
    account_id = session.get("account_id")
    if not account_id:
        return RedirectResponse("/account/login")

    conn = sqlite3.connect("accounts.db")
    c = conn.cursor()
    c.execute(
        "SELECT id, client_id, client_secret, name, redirect_uri, created_at FROM oauth_apps WHERE owner_account_id = ? ORDER BY created_at DESC",
        (account_id,),
    )
    rows = c.fetchall()
    conn.close()

    if not rows:
        apps_html = '<div class="empty-state"><p>You haven\'t registered any applications yet.</p><p style="color:var(--text-muted);font-size:0.9rem;">Create one above to get started!</p></div>'
    else:
        items = []
        for r in rows:
            app_id, client_id, client_secret, name, redirect_uri, created_at = r
            created_str = time.strftime("%Y-%m-%d %H:%M", time.localtime(created_at))
            items.append(
                f'<div class="app-item">'
                f'<div class="app-item-header">'
                f'<h3>{name}</h3>'
                f'<div class="app-item-actions">'
                f'<button class="btn btn-secondary btn-sm" onclick="confirmRegenerate({app_id})">Regenerate Secret</button>'
                f'<button class="btn btn-danger btn-sm" onclick="confirmDelete({app_id})">Delete</button>'
                f'</div></div>'
                f'<div class="app-detail"><span class="app-detail-label">Client ID</span>'
                f'<span class="app-detail-value" onclick="copyText(\'{client_id}\')" title="Click to copy" style="cursor:pointer;">{client_id}</span></div>'
                f'<div class="app-detail"><span class="app-detail-label">Client Secret</span>'
                f'<span class="app-detail-value secret-value" onclick="toggleSecret(this)" title="Click to reveal">{client_secret}</span></div>'
                f'<div class="app-detail"><span class="app-detail-label">Redirect URI</span>'
                f'<span class="app-detail-value">{redirect_uri}</span></div>'
                f'<div class="app-detail"><span class="app-detail-label">Created</span>'
                f'<span class="app-detail-value">{created_str}</span></div>'
                f'</div>'
            )
        apps_html = '<div class="app-list">' + "\n".join(items) + '</div>'

    # Load template
    file_path = os.path.join("static", "developer_apps.html")
    with open(file_path, "r", encoding="utf-8") as f:
        html = f.read()

    base_url = _get_base_url(request)
    html = html.replace("{{ base_url }}", base_url)
    html = html.replace("{{ apps_list }}", apps_html)

    # Inject topbar
    username = session.get("username") if isinstance(session, dict) else None
    if username:
        username_html = f'<div class="top-user">Signed in as <strong>{username}</strong> · <a href="/account/logout">Logout</a></div>'
    else:
        username_html = '<div class="top-user"><a href="/account/login">Login</a> · <a href="/account/create">Create Account</a></div>'
    html = html.replace("{{ topbar_account }}", username_html)

    return HTMLResponse(html)


@app.post("/developer/apps/create")
@limiter.limit("5/minute")
async def developer_create_app(
    request: Request,
    app_name: str = Form(..., min_length=1, max_length=64),
    redirect_uri: str = Form(..., max_length=512),
    session: dict = Depends(require_auth),
):
    account_id = session.get("account_id")
    if not account_id:
        raise HTTPException(403, "Login with a SitePhantom account first")

    # Validate redirect_uri is a proper URL
    parsed = urlparse(redirect_uri)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise HTTPException(400, "Invalid redirect URI — must be a full URL like https://example.com/callback")

    client_id = secrets.token_hex(16)
    client_secret = secrets.token_hex(32)

    conn = sqlite3.connect("accounts.db")
    c = conn.cursor()
    c.execute(
        "INSERT INTO oauth_apps (client_id, client_secret, name, redirect_uri, owner_account_id, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (client_id, client_secret, app_name, redirect_uri, account_id, time.time()),
    )
    conn.commit()
    conn.close()

    return RedirectResponse(url="/developer/apps", status_code=303)


@app.post("/developer/apps/{app_id}/delete")
@limiter.limit("10/minute")
async def developer_delete_app(request: Request, app_id: int, session: dict = Depends(require_auth)):
    account_id = session.get("account_id")
    if not account_id:
        raise HTTPException(403, "Forbidden")

    conn = sqlite3.connect("accounts.db")
    c = conn.cursor()
    c.execute("DELETE FROM oauth_apps WHERE id = ? AND owner_account_id = ?", (app_id, account_id))
    conn.commit()
    conn.close()

    return RedirectResponse(url="/developer/apps", status_code=303)


@app.post("/developer/apps/{app_id}/regenerate")
@limiter.limit("5/minute")
async def developer_regenerate_secret(request: Request, app_id: int, session: dict = Depends(require_auth)):
    account_id = session.get("account_id")
    if not account_id:
        raise HTTPException(403, "Forbidden")

    new_secret = secrets.token_hex(32)
    conn = sqlite3.connect("accounts.db")
    c = conn.cursor()
    c.execute("UPDATE oauth_apps SET client_secret = ? WHERE id = ? AND owner_account_id = ?", (new_secret, app_id, account_id))
    conn.commit()
    conn.close()

    return RedirectResponse(url="/developer/apps", status_code=303)


# --- OAuth2 Authorization Endpoint ---
@app.get("/oauth/authorize", response_class=HTMLResponse)
@limiter.limit("15/minute")
async def oauth_authorize_get(
    request: Request,
    client_id: str = Query(...),
    redirect_uri: str = Query(...),
    response_type: str = Query("code"),
    scope: str = Query("identify"),
):
    if response_type != "code":
        raise HTTPException(400, "Only response_type=code is supported")

    # Look up the app
    conn = sqlite3.connect("accounts.db")
    c = conn.cursor()
    c.execute("SELECT name, redirect_uri FROM oauth_apps WHERE client_id = ?", (client_id,))
    row = c.fetchone()
    conn.close()

    if not row:
        raise HTTPException(400, "Unknown client_id")

    app_name, registered_uri = row
    if redirect_uri != registered_uri:
        raise HTTPException(400, "redirect_uri does not match the registered URI")

    # User must be logged in
    session_data = get_current_session(request)
    if not session_data or "account_id" not in session_data:
        # Redirect to login, then back here (use path only for safety)
        from urllib.parse import urlencode
        oauth_path = str(request.url).replace(str(request.base_url).rstrip("/"), "")
        login_url = "/account/login?" + urlencode({"next": oauth_path})
        return RedirectResponse(login_url)

    username = session_data.get("username", "User")

    # Render consent screen
    file_path = os.path.join("static", "oauth_authorize.html")
    with open(file_path, "r", encoding="utf-8") as f:
        html = f.read()

    html = html.replace("{{ app_name }}", app_name)
    html = html.replace("{{ app_initial }}", app_name[0].upper() if app_name else "?")
    html = html.replace("{{ username }}", username)
    html = html.replace("{{ user_initial }}", username[0].upper() if username else "?")
    html = html.replace("{{ client_id }}", client_id)
    html = html.replace("{{ redirect_uri }}", redirect_uri)
    html = html.replace("{{ redirect_uri_display }}", urlparse(redirect_uri).netloc)
    html = html.replace("{{ scope }}", scope)

    return HTMLResponse(html)


@app.post("/oauth/authorize")
@limiter.limit("10/minute")
async def oauth_authorize_post(
    request: Request,
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    scope: str = Form("identify"),
    action: str = Form(...),
):
    session_data = get_current_session(request)
    if not session_data or "account_id" not in session_data:
        raise HTTPException(401, "Not authenticated")

    # Validate the app
    conn = sqlite3.connect("accounts.db")
    c = conn.cursor()
    c.execute("SELECT redirect_uri FROM oauth_apps WHERE client_id = ?", (client_id,))
    row = c.fetchone()
    if not row or row[0] != redirect_uri:
        conn.close()
        raise HTTPException(400, "Invalid client or redirect_uri")

    if action == "deny":
        conn.close()
        separator = "&" if "?" in redirect_uri else "?"
        return RedirectResponse(f"{redirect_uri}{separator}error=access_denied")

    # Generate authorization code
    code = secrets.token_urlsafe(48)
    now = time.time()
    c.execute(
        "INSERT INTO oauth_codes (code, client_id, account_id, redirect_uri, scope, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (code, client_id, session_data["account_id"], redirect_uri, scope, now),
    )
    conn.commit()
    conn.close()

    separator = "&" if "?" in redirect_uri else "?"
    return RedirectResponse(f"{redirect_uri}{separator}code={code}")


# --- OAuth2 Token Endpoint ---
@app.post("/oauth/token")
@limiter.limit("15/minute")
async def oauth_token(request: Request):
    form = await request.form()
    grant_type = form.get("grant_type")
    code = form.get("code")
    redirect_uri_param = form.get("redirect_uri")
    client_id = form.get("client_id")
    client_secret = form.get("client_secret")

    if grant_type != "authorization_code":
        raise HTTPException(400, "Unsupported grant_type")
    if not code or not client_id or not client_secret or not redirect_uri_param:
        raise HTTPException(400, "Missing required parameters")

    conn = sqlite3.connect("accounts.db")
    c = conn.cursor()

    # Validate client credentials
    c.execute("SELECT client_secret FROM oauth_apps WHERE client_id = ?", (client_id,))
    app_row = c.fetchone()
    if not app_row or app_row[0] != client_secret:
        conn.close()
        raise HTTPException(401, "Invalid client credentials")

    # Validate code
    c.execute(
        "SELECT account_id, redirect_uri, scope, created_at FROM oauth_codes WHERE code = ? AND client_id = ?",
        (code, client_id),
    )
    code_row = c.fetchone()
    if not code_row:
        conn.close()
        raise HTTPException(400, "Invalid or expired authorization code")

    account_id, stored_redirect, scope, created_at = code_row

    # Codes expire after 10 minutes
    if time.time() - created_at > 600:
        c.execute("DELETE FROM oauth_codes WHERE code = ?", (code,))
        conn.commit()
        conn.close()
        raise HTTPException(400, "Authorization code expired")

    if redirect_uri_param != stored_redirect:
        conn.close()
        raise HTTPException(400, "redirect_uri mismatch")

    # Delete the used code (single-use)
    c.execute("DELETE FROM oauth_codes WHERE code = ?", (code,))

    # Generate access token (valid for 24 hours)
    access_token = secrets.token_urlsafe(48)
    now = time.time()
    expires_at = now + 86400

    c.execute(
        "INSERT INTO oauth_tokens (access_token, client_id, account_id, scope, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
        (access_token, client_id, account_id, scope, now, expires_at),
    )
    conn.commit()
    conn.close()

    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 86400,
        "scope": scope,
    }


# --- OAuth2 User Info Endpoint ---
@app.get("/oauth/userinfo")
@limiter.limit("30/minute")
async def oauth_userinfo(request: Request):
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(401, "Missing or invalid Authorization header")

    token = auth_header[7:]

    conn = sqlite3.connect("accounts.db")
    c = conn.cursor()

    # Validate token
    c.execute(
        "SELECT account_id, scope, expires_at FROM oauth_tokens WHERE access_token = ?",
        (token,),
    )
    row = c.fetchone()
    if not row:
        conn.close()
        raise HTTPException(401, "Invalid access token")

    account_id, scope, expires_at = row
    if time.time() > expires_at:
        c.execute("DELETE FROM oauth_tokens WHERE access_token = ?", (token,))
        conn.commit()
        conn.close()
        raise HTTPException(401, "Access token expired")

    # Fetch user data
    c.execute(
        "SELECT id, username, discord_id, roblox_id FROM accounts WHERE id = ?",
        (account_id,),
    )
    user_row = c.fetchone()
    conn.close()

    if not user_row:
        raise HTTPException(404, "User not found")

    user_id, username, discord_id, roblox_id = user_row

    return {
        "id": user_id,
        "username": username,
        "discord_id": discord_id,
        "roblox_id": roblox_id,
    }