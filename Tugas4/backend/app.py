from fastapi import FastAPI, HTTPException, Depends, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import sqlite3
from passlib.context import CryptContext
import hashlib
import uuid
from typing import List, Optional
import json
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

app = FastAPI()
DATABASE = "database.db"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
sessions = {}

app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
)

class User(BaseModel):
        username: str
        password: str
        role: str

class LoginInput(BaseModel):
        username: str
        password: str
        
class Course(BaseModel):
        course_code: str
        course_name: str
        credits: int
        grade: float

class TranscriptInput(BaseModel):
        nim: str
        name: str
        courses: list[Course]
        
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
        
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users';")
        if cursor.fetchone() is None:
                with open("schema.sql", "r") as f:
                        conn.executescript(f.read())
                conn.commit()
                
                # Buat testing
                default_users = [
                        ("admin_if", pwd_context.hash("password123"), "Ketua Program Studi"),
                        ("admin_sti", pwd_context.hash("password123"), "Ketua Program Studi"),
                        ("dosen1", pwd_context.hash("password123"), "Dosen Wali"),
                        ("dosen2", pwd_context.hash("password123"), "Dosen Wali"),
                        ("18222001", pwd_context.hash("password123"), "Mahasiswa"),
                        ("18222002", pwd_context.hash("password123"), "Mahasiswa"),
                ]
                
                cursor.executemany(
                        "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                        default_users
                )
                conn.commit()
        conn.close()

def calculate_ipk(courses: List[Course]) -> float:
        total_credits = 0
        total_grade_points = 0
        
        for course in courses:
                grade_point = course.grade
                total_credits += course.credits
                total_grade_points += grade_point * course.credits
        
        return round(total_grade_points / total_credits, 2) if total_credits > 0 else 0.0

def get_current_user(request: Request, db: sqlite3.Connection = Depends(get_db)):
        session_id = request.cookies.get("session_id")
        if not session_id or session_id not in sessions:
                raise HTTPException(status_code=401, detail="Not authenticated")
        
        user_id = sessions[session_id]["user_id"]
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        
        if not user:
                raise HTTPException(status_code=401, detail="User not found")
        
        return user

def require_role(allowed_roles: List[str]):
        def role_checker(current_user = Depends(get_current_user)):
                if current_user["role"] not in allowed_roles:
                        raise HTTPException(status_code=403, detail="Insufficient permissions")
                return current_user
        return role_checker

@app.on_event("startup")
async def startup_event():
        init_db()
        
@app.post("/register")
def register(user: User, db: sqlite3.Connection = Depends(get_db)):
        if user.role == "Ketua Program Studi":
                cursor = db.cursor()
                cursor.execute("SELECT COUNT(*) as count FROM users WHERE role = 'Ketua Program Studi'")
                count = cursor.fetchone()["count"]
                if count >=2:
                        raise HTTPException(status_code=400, detail="Maximum 2 ketua program studi")
                
        cursor = db.cursor()
        hashed = pwd_context.hash(user.password)
        
        try:
                cursor.execute(
                        "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                        (user.username, hashed, user.role),
                )
                db.commit()
        except sqlite3.IntegrityError:
                raise HTTPException(status_code=400, detail="Username already exists")
        return {"message": "User registered successfully"}

@app.post("/login")
def login(login_input: LoginInput, response: Response, db: sqlite3.Connection = Depends(get_db)):
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (login_input.username,))
        user = cursor.fetchone()
        
        if user is None or not pwd_context.verify(login_input.password, user["password"]):
                raise HTTPException(status_code=401, detail="Invalid username or password")

        session_id = str(uuid.uuid4())
        sessions[session_id] = {
                "user_id": user["id"],
                "username": user["username"],
                "role": user["role"]
        }
        
        response.set_cookie(key="session_id", value=session_id, httponly=True)
        return {
                "message": "Login successful",
                "user": {
                        "username": user["username"],
                        "role": user["role"]
                }
        }
        
@app.post("/logout")
def logout(request: Request, response: Response):
        session_id = request.cookies.get("session_id")
        if session_id and session_id in sessions:
                del sessions[session_id]
        response.delete_cookie(key="session_id")
        return {"message": "Logged out successfully"}


# Bawah pake AI, belum aku cek 100% kode nya tapi pas testing it seems correct
@app.post("/transcript/input")
def input_transcript(
    transcript_data: TranscriptInput,
    db: sqlite3.Connection = Depends(get_db),
    current_user = Depends(require_role(["Dosen Wali"]))
):
    if len(transcript_data.courses) != 10:
        raise HTTPException(status_code=400, detail="Exactly 10 courses required")
    
    # Calculate IPK
    ipk = calculate_ipk(transcript_data.courses)
    
    # Encrypt transcript data (simplified AES encryption)
    key = get_random_bytes(32)  # AES-256 key
    cipher = AES.new(key, AES.MODE_GCM)
    
    transcript_json = {
        "nim": transcript_data.nim,
        "name": transcript_data.name,
        "courses": [course.dict() for course in transcript_data.courses],
        "ipk": ipk
    }
    
    ciphertext, tag = cipher.encrypt_and_digest(json.dumps(transcript_json).encode())
    encrypted_data = base64.b64encode(cipher.nonce + tag + ciphertext).decode()
    
    # Create digital signature (simplified with SHA-3)
    signature_data = f"{transcript_data.nim}{transcript_data.name}{ipk}".encode()
    signature = hashlib.sha3_256(signature_data).hexdigest()
    
    cursor = db.cursor()
    cursor.execute(
        "INSERT INTO transcripts (nim, name, encrypted_data, ipk, signature, created_by) VALUES (?, ?, ?, ?, ?, ?)",
        (transcript_data.nim, transcript_data.name, encrypted_data, ipk, signature, current_user["id"])
    )
    transcript_id = cursor.lastrowid
    
    # Store courses
    for course in transcript_data.courses:
        grade_point = course.grade
        cursor.execute(
            "INSERT INTO courses (transcript_id, course_code, course_name, credits, grade) VALUES (?, ?, ?, ?, ?)",
            (transcript_id, course.course_code, course.course_name, course.credits, course.grade)
        )
    
    db.commit()
    
    return {
        "message": "Transcript saved successfully",
        "transcript_id": transcript_id,
        "ipk": ipk,
        "signature": signature
    }

@app.get("/transcript/list")
def list_transcripts(
    db: sqlite3.Connection = Depends(get_db),
    current_user = Depends(get_current_user)
):
    cursor = db.cursor()
    
    if current_user["role"] == "Mahasiswa":
        # Students can only see their own transcript
        cursor.execute(
            "SELECT id, nim, name, ipk, created_at FROM transcripts WHERE nim = ?",
            (current_user["username"],)
        )
    elif current_user["role"] == "Dosen Wali":
        # Dosen Wali can see transcripts they created
        cursor.execute(
            "SELECT id, nim, name, ipk, created_at FROM transcripts WHERE created_by = ?",
            (current_user["id"],)
        )
    elif current_user["role"] == "Ketua Program Studi":
        # Ketua Program Studi can see all transcripts
        cursor.execute("SELECT id, nim, name, ipk, created_at FROM transcripts")
    
    transcripts = cursor.fetchall()
    return {"transcripts": [dict(t) for t in transcripts]}

@app.get("/user/profile")
def get_profile(current_user = Depends(get_current_user)):
    return {
        "username": current_user["username"],
        "role": current_user["role"]
    }