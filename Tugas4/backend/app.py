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
from Crypto.Util.Padding import pad, unpad
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
        major: str

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
        aes_key_hex: str
        
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
                        ("admin_if", pwd_context.hash("password123"), "Ketua Program Studi", "IF"),
                        ("admin_sti", pwd_context.hash("password123"), "Ketua Program Studi", "STI"),
                        ("dosen1", pwd_context.hash("password123"), "Dosen Wali", "IF"),
                        ("dosen2", pwd_context.hash("password123"), "Dosen Wali", "STI"),
                        ("dosen3", pwd_context.hash("password123"), "Dosen Wali", "STI"),
                        ("18222001", pwd_context.hash("password123"), "Mahasiswa", "STI"),
                        ("18222002", pwd_context.hash("password123"), "Mahasiswa", "STI"),
                ]
                
                cursor.executemany(
                        "INSERT INTO users (username, password, role, major) VALUES (?, ?, ?, ?)",
                        default_users
                )
                conn.commit()
        conn.close()

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

def calculate_ipk(courses: List[Course]) -> float:
        total_credits = 0
        total_grade_points = 0
        
        for course in courses:
                grade_point = course.grade
                total_credits += course.credits
                total_grade_points += grade_point * course.credits
        
        return round(total_grade_points / total_credits, 2) if total_credits > 0 else 0.0

def encrypt_aes_cbc(data: str, key_hex: str) -> str:
        key = bytes.fromhex(key_hex)
        data_bytes = data.encode('utf-8')

        cipher = AES.new(key, AES.MODE_CBC)
        iv = cipher.iv 
        ct_bytes = cipher.encrypt(pad(data_bytes, AES.block_size))

        encrypted_data_with_iv = iv + ct_bytes
        return base64.b64encode(encrypted_data_with_iv).decode('utf-8')

def decrypt_aes_cbc(encrypted_data: str, key_hex: str) -> str:
        key = bytes.fromhex(key_hex)
        encrypted_data = base64.b64decode(encrypted_data)

        iv = encrypted_data[:AES.block_size] # Extract IV
        ct = encrypted_data[AES.block_size:] # Extract ciphertext

        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt_bytes = unpad(cipher.decrypt(ct), AES.block_size)
        return pt_bytes.decode('utf-8')

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

@app.get("/user/profile")
def get_profile(current_user = Depends(get_current_user)):
    return {
        "username": current_user["username"],
        "role": current_user["role"]
    }

@app.post("/transcript/input")
def input_transcript(
        transcript_data: TranscriptInput,
        db: sqlite3.Connection = Depends(get_db),
        current_user = Depends(require_role(["Dosen Wali"]))
):
        # Validate courses
        if len(transcript_data.courses) != 10:
                raise HTTPException(status_code=400, detail="Exactly 10 courses required")

        # Validate AES key
        if not transcript_data.aes_key_hex: 
                raise HTTPException(status_code=400, detail="AES key cannot be empty")          
        if len(transcript_data.aes_key_hex) != 64:  # 32 bytes for AES-256
                raise HTTPException(status_code=400, detail="AES key must be 64 hexadecimal characters (32 bytes)")     
        try:
                bytes.fromhex(transcript_data.aes_key_hex)
        except ValueError:      
                raise HTTPException(status_code=400, detail="Invalid AES key format, must be hexadecimal")                      

        # Calculate IPK
        ipk = calculate_ipk(transcript_data.courses)

        data = {
                "nim": transcript_data.nim,
                "name": transcript_data.name,
                "courses": [course.dict() for course in transcript_data.courses],
                "ipk": ipk,
        }
        data_json = json.dumps(data, indent=4)

        # Encrypt transcript data with AES
        try:
                encrypted_data = encrypt_aes_cbc(data_json, transcript_data.aes_key_hex)
        except ValueError as e:
                raise HTTPException(status_code=400, detail=f"AES Encryption error: {str(e)}")
        except Exception as e:
                raise HTTPException(status_code=500, detail=f"Unexpected error during encryption: {str(e)}")
    
        # Create digital signature (simplified with SHA-3)
        signature_data = f"{transcript_data.nim}{transcript_data.name}{ipk}".encode()
        signature = hashlib.sha3_256(signature_data).hexdigest()
    
        # Store transcript in database
        try:
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
        except sqlite3.Error as e:
                raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    
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

        base_query = "SELECT t.id, t.nim, t.name, t.ipk, t.created_at, u.username AS created_by_usn FROM transcripts t JOIN users u ON t.created_by = u.id"
        
        try:
                if current_user["role"] == "Mahasiswa":
                        # Students can only see their own transcript
                        cursor.execute(
                                cursor.execute(f"{base_query} WHERE t.nim = ?", (current_user["username"],))
                        )
                elif current_user["role"] == "Dosen Wali" or current_user["role"] == "Dosen Wali":
                        # Dosen Wali and Ketua Program Studi can list all transcripts
                        cursor.execute(cursor.execute(f"{base_query} WHERE t.created_by = ?", (current_user["id"],))
                        )
                else:
                        raise HTTPException(status_code=403, detail="Insufficient permissions to view transcripts")
        except sqlite3.Error as e:
                raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
            
        transcripts = cursor.fetchall()

        return {"transcripts": [dict(t) for t in transcripts]}

@app.get("/transcript/{transcript_id}")
def get_transcript_detail(
        transcript_id: int,
        db: sqlite3.Connection = Depends(get_db),
        current_user = Depends(get_current_user)
):
        cursor = db.cursor()

        cursor.execute(
                "SELECT t.id, t.nim, t.name, t.encrypted_data, t.ipk, t.signature, t.created_at, u.username AS created_by_usn "
                "FROM transcripts t JOIN users u ON t.created_by = u.id WHERE t.id = ?",
                (transcript_id,)
        )       

        transcript = cursor.fetchone()

        if current_user["role"] == "Mahasiswa" and transcript["nim"] != current_user["username"]:
                raise HTTPException(status_code=403, detail="You can only view your own transcript")
        if current_user["role"] == "Dosen Wali" and transcript["created_by_usn"] != current_user["username"]:
                # TODO: implement SSS
                raise HTTPException(status_code=403, detail="You can only view transcripts you created")
        
        if not transcript:
                raise HTTPException(status_code=404, detail="Transcript not found")
        
        transcript = dict(transcript)

        # Fetch courses
        try:
                cursor.execute(
                        "SELECT course_code, course_name, credits, grade FROM courses WHERE transcript_id = ?",
                        (transcript_id,)
                )
                courses = cursor.fetchall()
        except sqlite3.Error as e:
                raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

        transcript["courses"] = [dict(course) for course in courses]

        # Decrypt transcript data
        # try:
        #         decrypted_data = decrypt_aes_cbc(transcript["encrypted_data"], transcript["aes_key_hex"])
        #         transcript_json = json.loads(decrypted_data)
        # except ValueError as e:
        #         raise HTTPException(status_code=400, detail=f"AES Decryption error: {str(e)}")
        # except Exception as e:
        #         raise HTTPException(status_code=500, detail=f"Unexpected error during decryption: {str(e)}")

        return transcript