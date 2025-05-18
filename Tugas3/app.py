import sqlite3
import os
import datetime
from fastapi import FastAPI, Form, HTTPException, Depends, Request, status
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from cryptography.hazmat.primitives import serialization
from passlib.hash import bcrypt 

DATABASE = "chatroom.db"
app = FastAPI()
# TODO: To be edited kalo pindah ke NextJS
app.mount("/static", StaticFiles(directory="static", html=True), name="static")

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

@app.on_event("startup")
async def startup_event():
        init_db()

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
                    db: sqlite3.Connection = Depends(get_db)):
        """Login user and return user info"""
        
        def _login_db_call():
                user = db.execute("SELECT id, username, password FROM users WHERE username = ?", (username,)).fetchone()
                if not user or not bcrypt.verify(password, user["password"]):
                        return None
                return {"id": user["id"], "username": user["username"]}
        
        user_info = await run_in_threadpool(_login_db_call)
        if user_info is None:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")
        
        return {"message": "Login successful", "user": user_info}

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
async def get_messages(sender: str, receiver: str, db: sqlite3.Connection = Depends(get_db)):
        """Retrieve messages between two users"""
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