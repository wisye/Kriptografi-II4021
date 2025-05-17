import sqlite3
import os
import datetime
from fastapi import FastAPI, Form, HTTPException, Depends, Request, status
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel
from typing import List
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from cryptography.hazmat.primitives import serialization
from passlib.hash import bcrypt 

DATABASE = "chatroom.db"
app = FastAPI()
app.mount("/static", StaticFiles(directory="static", html=True), name="static")

class UserCreate(BaseModel):
        username : str
        password : str

class MessageCreate(BaseModel):
        sender_usn : str
        receiver_usn : str
        content : str

class MessageResponse(BaseModel):
        id : int
        sender_usn : str
        receiver_usn : str
        content : str
        hashed_content : str
        signature : str
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
        if not user_data.username or not user_data.password:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username and password are required")

        user = db.execute("SELECT id FROM users WHERE username = ?", (user_data.username,)).fetchone()
        if user:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already registered")
        
        # Hash the password
        hashed_pass = bcrypt.hash(user_data.password)

        # Generate ECDSA key pair
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()

        serialized_private = private_key.private_bytes( 
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()       
        )
        serialized_public = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        db.execute("INSERT INTO users (username, hashed_pass, private_key, public_key) VALUES (?, ?)", (user_data.username, hashed_pass, serialized_private, serialized_public))
        db.commit()
        return {"message": "User registered"}

@app.post("/api/login")
async def api_login(username: str = Form(...),
                    password: str = Form(...),
                    db: sqlite3.Connection = Depends(get_db)):
        
        def _login_db_call():
                user = db.execute("SELECT id, username, password FROM users WHERE username = ?", (username,)).fetchone()
                if not user or not bcrypt.verify(password, user["hashed_pass"]):
                        return None
                return {"id": user["id"], "username": user["username"]}
        
        user_info = await run_in_threadpool(_login_db_call)
        if user_info is None:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")
        
        return {"message": "Login successful", "user": user_info}

@app.get("/api/users", response_model=List[str])
async def get_users(db: sqlite3.Connection = Depends(get_db)):  
        def _get_users_db_call():
                users_cursor = db.execute(
                        'SELECT username FROM users ORDER BY username ASC LIMIT 100'
                )
                return users_cursor.fetchall()
        
        users_rows = await run_in_threadpool(_get_users_db_call)
        return [dict(user) for user in users_rows]

@app.get("/api/messages", response_model=List[MessageResponse])
async def get_messages(db: sqlite3.Connection = Depends(get_db)):
        
        def _get_messages_db_call():
                messages_cursor = db.execute(
                        'SELECT id, username, content, timestamp FROM messages ORDER BY timestamp ASC LIMIT 100'
                )
                return messages_cursor.fetchall()
        
        messages_rows = await run_in_threadpool(_get_messages_db_call)
        return [MessageResponse(**dict(msg)) for msg in messages_rows]

@app.post("/api/messages", response_model=MessageResponse)
async def create_message(message: MessageCreate, db: sqlite3.Connection = Depends(get_db)):
        if not message.receiver_usn.strip() or not message.content.strip():
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Recipient and message cannot be empty")
        
        hash = hashes.Hash(hashes.SHA3_256())
        hash.update(message.content.encode('utf-8'))
        hashed_content = hash.finalize().hex()

        def _get_user_private_key():
                user = db.execute("SELECT private_key FROM users WHERE username = ?", (message.sender_usn,)).fetchone()
                if not user:
                        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
                return serialization.load_pem_private_key(user["private_key"], password=None)
        
        
        private_key = await run_in_threadpool(_get_user_private_key)
        if not private_key:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Private key not found")
        signature = private_key.sign(hashed_content, ec.ECDSA(hashes.SHA3_256())).hex() 

        def _create_message_db_call():
                cursor = db.execute(
                        "INSERT INTO messages (sender_usn, receiver_usn, content, hashed_content, signature) VALUES (?, ?, ?)",
                        (message.sender_usn, message.receiver_usn, message.content, hashed_content, signature)
                )
                db.commit()
                message_id = cursor.lastrowid
                created_message = db.execute(
                        'SELECT id, sender_usn, receiver_usn, content, hashed_content, timestamp FROM messages WHERE id = ?', (message_id,)
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