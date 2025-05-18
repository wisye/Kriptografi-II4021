import sqlite3
import os
import datetime
import secrets
from fastapi import FastAPI, Form, HTTPException, Depends, Request, status
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import List
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from cryptography.hazmat.primitives import serialization
from passlib.hash import bcrypt 
from datetime import datetime, timedelta

DATABASE = "chatroom.db"
app = FastAPI()
# TODO: To be edited kalo pindah ke NextJS
app.mount("/static", StaticFiles(directory="static", html=True), name="static")
security = HTTPBearer(auto_error=False)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class UserCreate(BaseModel):
        username : str
        password : str
        public_key_x : str
        public_key_y : str

class UserResponse(BaseModel):
        id : int
        username : str
        public_key_x : str
        public_key_y : str

class MessageCreate(BaseModel):
        sender : str
        receiver : str
        content : str
        content_hash: str
        signature_r: str
        signature_s: str

class MessageResponse(BaseModel):
        id : int
        sender : str
        receiver : str
        content : str
        content_hash: str
        signature_r: str
        signature_s: str
        timestamp : datetime.datetime

def get_db():
        db = sqlite3.connect(DATABASE, check_same_thread=False)
        db.row_factory = sqlite3.Row
        try:
                yield db
        finally:
                db.close()
                
def init_db():
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Check if table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users';")
        if cursor.fetchone() is None:
                with open("schema.sql", "r") as f:
                        conn.executescript(f.read())
                conn.commit()
        conn.close()

def create_session_token():
        return secrets.token_hex(32)

def get_session_expiry():
        return datetime.now() + timedelta(days=1)

async def get_current_user(
        token: HTTPAuthorizationCredentials = Depends(security),
        request: Request = None,
        db: sqlite3.Connection = Depends(get_db)
):
        session_token = None
        if token:
                session_token = token.credentials
        
        if not session_token and request:
                session_token = request.cookies.get("session_token")
        
        if not session_token:
                return
        
        def _get_user_from_token():
                session_row = db.execute(
                """SELECT s.user_id, u.username, u.public_key_x, u.public_key_y, s.expires_at
                FROM sessions s
                JOIN users u ON s.user_id = u.id
                WHERE s.session_token = ? AND datetime(s.expires_at) > datetime('now')
                """, (session_token,)).fetchone()
                
                if not session_row:
                        return
                
                return {
                "id": session_row["user_id"],
                "username": session_row["username"],
                "public_key_x": session_row["public_key_x"],
                "public_key_y": session_row["public_key_y"]
                }
    
        user = await run_in_threadpool(_get_user_from_token)
        return user

async def auth(current_user=Depends(get_current_user)):
        if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
        return current_user
        
@app.on_event("startup")
async def startup_event():
        init_db()
        conn = sqlite3.connect(DATABASE)
        conn.execute("DELETE FROM sessions WHERE datetime(expires_at) <= datetime('now')")
        conn.commit()
        conn.close()

@app.get("/api/me")
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
        if not current_user:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
        return current_user

@app.post("/api/register")
def api_register(user_data: UserCreate, db: sqlite3.Connection = Depends(get_db)):
        """Register a new user"""
        if not user_data.username or not user_data.password:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username and password are required")

        user = db.execute("SELECT id FROM users WHERE username = ?", (user_data.username,)).fetchone()
        if user:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already registered")
        
        hashed_pass = bcrypt.hash(user_data.password)
        
        db.execute("INSERT INTO users (username, password, public_key_x, public_key_y) VALUES (?, ?, ?, ?)", (user_data.username, hashed_pass, user_data.public_key_x, user_data.public_key_y))
        db.commit()
        return {"message": "User registered"}

@app.post("/api/login")
async def api_login(username: str = Form(...),
                    password: str = Form(...),
                    db: sqlite3.Connection = Depends(get_db),
                    response: Response = None):
        """Login user and return user info"""
        
        def _login_db_call():
                user = db.execute("SELECT id, username, password, public_key_x, public_key_y FROM users WHERE username = ?", (username,)).fetchone()
                if not user or not bcrypt.verify(password, user["password"]):
                        return None
                
                active_session = db.execute("SELECT session_token FROM sessions WHERE user_id = ? AND datetime(expires_at) > datetime('now')", (user["id"],)).fetchone()
                if active_session:
                        return {"error": "already_logged_in"}
                
                session_token = create_session_token()
                expires_at = get_session_expiry()
                
                db.execute(
                        "INSERT INTO sessions (user_id, session_token, expires_at) VALUES (?, ?, ?)",
                        (user["id"], session_token, expires_at)
                )
                db.commit()
                
                return {
                        "user": {
                                "id": user["id"], 
                                "username": user["username"],
                                "public_key_x": user["public_key_x"],
                                "public_key_y": user["public_key_y"]
                        },
                        "session_token": session_token,
                        "expires_at": expires_at.isoformat()
                }
        
        user_info = await run_in_threadpool(_login_db_call)
        if user_info is None:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")
        if "error" in user_info and user_info["error"] == "already_logged_in":
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="User already logged in")
        
        response.set_cookie(
                key="session_token",
                value=user_info["session_token"],
                httponly=True,
                secure=False, # Change to True in prod with HTTPS
                samesite="lax",
                max_age=86400
        )
        
        return {"message": "Login successful", "user": user_info["user"], "session_token": user_info["session_token"], "expires_at": user_info["expires_at"]}

@app.post("/api/logout")
async def logout(
        response: Response = None,
        current_user: dict = Depends(get_current_user),
        request: Request = None,
        db: sqlite3.Connection = Depends(get_db)
):
        if not current_user:
                return {"message": "Not logged in"}
        
        session_token = request.cookies.get("session_token")
        if session_token:
                def _logout_db_call():
                        db.execute("DELETE FROM sessions WHERE session_token = ?",(session_token,))
                        db.commit()
                
                await run_in_threadpool(_logout_db_call)
        
        response.delete_cookie(key="session_token")
        return {"message: Logout succesful"}
                
@app.get("/api/users", response_model=List[UserResponse])
async def get_users(user: str, db: sqlite3.Connection = Depends(get_db)):  
        """Retrieve all users except the logged-in user"""
        def _get_users_db_call():
                users_cursor = db.execute(
                        'SELECT id, username, public_key_x, public_key_y FROM users WHERE username != ?', (user,)
                )
                return users_cursor.fetchall()

        users_rows = await run_in_threadpool(_get_users_db_call)
        return [UserResponse(**dict(user)) for user in users_rows]

@app.get("/api/messages/{sender}/{receiver}", response_model=List[MessageResponse])
async def get_messages(sender: str, receiver: str, db: sqlite3.Connection = Depends(get_db), current_user: dict = Depends(auth)):
        """Retrieve messages between two users"""
        if sender != current_user["username"]:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
        
        def _get_messages_db_call():
                messages_cursor = db.execute(
                        """
                        SELECT id, sender, receiver, content, content_hash, signature_r, signature_s, timestamp 
                        FROM messages 
                        WHERE (sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?)
                        ORDER BY timestamp ASC
                        """, (sender, receiver, receiver, sender)
                )
                return messages_cursor.fetchall()
        
        messages_rows = await run_in_threadpool(_get_messages_db_call)
        return [MessageResponse(**dict(msg)) for msg in messages_rows]

@app.post("/api/messages", response_model=MessageResponse)
async def create_message(message: MessageCreate, db: sqlite3.Connection = Depends(get_db)):
        """Create a new message"""
        if not all([message.sender.strip(), message.receiver.strip(), message.content.strip(), message.content_hash.strip(), message.signature_r.strip(), message.signature_s.strip()]):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Any fields in the message cannot be empty")

        def _create_message_db_call():
                cursor = db.execute(
                        "INSERT INTO messages (sender, receiver, content, content_hash, signature_r, signature_s) VALUES (?, ?, ?, ?, ?, ?)",
                        (message.sender, message.receiver, message.content, message.content_hash, message.signature_r, message.signature_s)
                )
                db.commit()
                message_id = cursor.lastrowid
                created_message = db.execute(
                        'SELECT id, sender, receiver, content, content_hash, signature_r, signature_s, timestamp FROM messages WHERE id = ?', (message_id,)
                ).fetchone()
                if not create_message:
                        return None
                return MessageResponse(**dict(created_message))

        create_message_response = await run_in_threadpool(_create_message_db_call)
        if create_message_response is None:
                raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Could not retrieve created message")
        return create_message_response

@app.get("/{path:path}")
async def serve_static_or_index(path: str):
    static_file_path = os.path.join("static", path)
    if path == "" or path == "/": # Serve login.html as the default for root
        return FileResponse(os.path.join("static", "login.html"))
    if os.path.exists(static_file_path) and os.path.isfile(static_file_path):
        return FileResponse(static_file_path)
    # Fallback for SPA-like behavior or if direct .html access is desired
    if not "." in path and os.path.exists(os.path.join("static", f"{path}.html")):
         return FileResponse(os.path.join("static", f"{path}.html"))
    # If specific file not found, try serving login.html as a general fallback for undefined routes
    # or raise 404 if you prefer stricter routing.
    # For this simple case, let's try login.html or a 404.
    # If you want any undefined path to go to login:
    # return FileResponse(os.path.join("static", "login.html"))
    raise HTTPException(status_code=404, detail="Page not found")