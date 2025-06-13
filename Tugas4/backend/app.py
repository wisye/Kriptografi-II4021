from fastapi import FastAPI, HTTPException, Depends, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import sqlite3
from passlib.context import CryptContext
import hashlib
import uuid
from typing import List, Optional, Tuple
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
from keys_config import KAPRODI_RSA_KEYS

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

class AcademicInput(BaseModel):
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

def hex_to_int(hex_str: str) -> int:
        try:
                return int(hex_str, 16)
        except ValueError:
                raise HTTPException(status_code=400, detail="Invalid hexadecimal string")
        
def int_to_hex(value: int) -> str:
        if value < 0:
                raise HTTPException(status_code=400, detail="Value must be non-negative")
        return hex(value)[2:].zfill(64)

def rsa_encrypt(data_int: int, public_key_tuple: Tuple[int, int]) -> int:
        e, n = public_key_tuple
        if data_int >= n:
                raise HTTPException(status_code=400, detail="Data to encrypt mut be numerically smaller than RSA modulus n")
        ciphertext_int = pow(data_int, e, n)
        return ciphertext_int

def rsa_decrypt(encrypted_data_int: int, private_key_tuple: Tuple[int, int]) -> int:
        d, n = private_key_tuple
        if encrypted_data_int >= n:
                raise HTTPException(status_code=400, detail="Encrypted data must be numerically smaller than RSA modulus n")
        plaintext_int = pow(encrypted_data_int, d, n)
        return plaintext_int

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

@app.post("/academic/input")
def input_academic(
        academic_data: AcademicInput,
        db: sqlite3.Connection = Depends(get_db),
        current_user = Depends(require_role(["Dosen Wali"]))
):
        # Validate courses
        if len(academic_data.courses) != 10:
                raise HTTPException(status_code=400, detail="Exactly 10 courses required")

        # Validate AES key
        if not academic_data.aes_key_hex: 
                raise HTTPException(status_code=400, detail="AES key cannot be empty")          
        if len(academic_data.aes_key_hex) != 64:  # 32 bytes for AES-256
                raise HTTPException(status_code=400, detail="AES key must be 64 hexadecimal characters (32 bytes)")     
        try:
                bytes.fromhex(academic_data.aes_key_hex)
        except ValueError:      
                raise HTTPException(status_code=400, detail="Invalid AES key format, must be hexadecimal")                      

        # Calculate IPK
        ipk = calculate_ipk(academic_data.courses)

        data = {
                "nim": academic_data.nim,
                "name": academic_data.name,
                "courses": [course.dict() for course in academic_data.courses],
                "ipk": ipk,
        }
        data_json = json.dumps(data, indent=4)

        # Encrypt academic data with AES
        try:
                encrypted_data = encrypt_aes_cbc(data_json, academic_data.aes_key_hex)
        except ValueError as e:
                raise HTTPException(status_code=400, detail=f"AES Encryption error: {str(e)}")
        except Exception as e:
                raise HTTPException(status_code=500, detail=f"Unexpected error during encryption: {str(e)}")
        
        # Encrypt AES key with RSA
        major = current_user["major"]
        if major not in KAPRODI_RSA_KEYS:
                raise HTTPException(status_code=400, detail="Invalid major for encryption keys")
        public_key = KAPRODI_RSA_KEYS[major]["public"]
        try:
                aes_key = hex_to_int(academic_data.aes_key_hex)
                encrypted_aes_key = rsa_encrypt(aes_key, (public_key["e"], public_key["n"]))
                encrypted_aes_key = int_to_hex(encrypted_aes_key)
        except Exception as e:
                raise HTTPException(status_code=500, detail=f"RSA Encryption error: {str(e)}")

        # Hash academic data
        try:
                hashed_data = hashlib.sha3_256(data_json.encode()).hexdigest()
        except Exception as e:
                raise HTTPException(status_code=500, detail=f"Hashing error: {str(e)}")

        # Create digital signature (simplified with SHA-3)
        signature = hashlib.sha3_256(data_json.encode()).hexdigest()
        if not signature:
                raise HTTPException(status_code=500, detail="Failed to create digital signature")
    
        # Store academic in database
        try:
                cursor = db.cursor()
                cursor.execute(
                        "INSERT INTO academics (nim, name, encrypted_data, encrypted_key, hashed_data, signature, created_by) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (academic_data.nim, academic_data.name, encrypted_data, encrypted_aes_key, hashed_data, signature, current_user["id"])
                )
                academic_id = cursor.lastrowid
                db.commit()
        except sqlite3.Error as e:
                raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    
        return {
                "message": "academic saved successfully",
                "academic_id": academic_id,
                "ipk": ipk,
                "signature": signature
        }

@app.get("/academic/list")
def list_academics(
        db: sqlite3.Connection = Depends(get_db),
        current_user = Depends(get_current_user)
):
        cursor = db.cursor()

        base_query = "SELECT t.id, t.nim, t.name, t.created_at, u.username AS created_by_usn FROM academics t JOIN users u ON t.created_by = u.id"
        
        try:
                if current_user["role"] == "Mahasiswa":
                        # Students can only see their own academic
                        cursor.execute(f"{base_query} WHERE t.nim = ?", (current_user["username"],))
                elif current_user["role"] == "Dosen Wali" or current_user["role"] == "Dosen Wali":
                        # Dosen Wali and Ketua Program Studi can list all academics
                        cursor.execute(f"{base_query} WHERE t.created_by = ?", (current_user["id"],))
                else:
                        raise HTTPException(status_code=403, detail="Insufficient permissions to view academics")
        except sqlite3.Error as e:
                raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
            
        academics = cursor.fetchall()

        return {"academics": [dict(t) for t in academics]}

@app.get("/academic/{academic_id}")
def get_academic_detail(
        academic_id: int,
        aes_key_hex: Optional[str] = None,
        db: sqlite3.Connection = Depends(get_db),
        current_user = Depends(get_current_user)
):
        cursor = db.cursor()

        cursor.execute(
                "SELECT t.id, t.nim, t.name, t.encrypted_data, t.encrypted_key, t.hashed_data, t.signature, t.created_at, u.username AS created_by_usn "
                "FROM academics t JOIN users u ON t.created_by = u.id WHERE t.id = ?",
                (academic_id,)
        )       

        academic = cursor.fetchone()

        if not academic:
                raise HTTPException(status_code=404, detail="academic not found")
        
        if current_user["role"] == "Mahasiswa" and academic["nim"] != current_user["username"]:
                raise HTTPException(status_code=403, detail="You can only view your own academic")
        
        academic = dict(academic)
        
        if current_user["role"] == "Dosen Wali" and academic["created_by_usn"] == current_user["username"] or current_user["role"] == "Mahasiswa" and academic["nim"] == current_user["username"]:
                academic["aes_key_hex"] = aes_key_hex
        elif academic["created_by_usn"] != current_user["username"] and current_user["role"] != "Dosen Wali":
                # TODO: implement SSS
                raise HTTPException(status_code=403, detail="You do not have permission to view this academic's AES key")
        elif current_user["role"] == "Ketua Program Studi":
                # Decrypt AES key using private RSA key
                major = current_user["major"]
                if major not in KAPRODI_RSA_KEYS:
                        raise HTTPException(status_code=400, detail="Invalid major for decryption keys")
                private_key = KAPRODI_RSA_KEYS[major]["private"]
                try:
                        encrypted_aes_key = hex_to_int(academic["encrypted_key"])
                        decrypted_aes_key = rsa_decrypt(encrypted_aes_key, (private_key["d"], private_key["n"]))
                        academic["aes_key_hex"] = int_to_hex(decrypted_aes_key)
                except Exception as e:
                        raise HTTPException(status_code=500, detail=f"Decrypting AES key error: {str(e)}")

        # Decrypt academic data
        try:
                decrypted_data = decrypt_aes_cbc(academic["encrypted_data"], academic["aes_key_hex"])
                decrypted_json = json.loads(decrypted_data)
        except ValueError as e:
                raise HTTPException(status_code=400, detail=f"academic's AES Decryption error: {str(e)}")
        except Exception as e:
                raise HTTPException(status_code=500, detail=f"Unexpected error during academic decryption: {str(e)}")
        
        response_json = {
                "id": academic["id"],
                "nim": decrypted_json["nim"],
                "name": decrypted_json["name"],
                "courses": decrypted_json["courses"],
                "ipk": decrypted_json["ipk"],
                "hashed_data": academic["hashed_data"],
                "signature": academic["signature"],
                "kaprodi_public_key": {
                        "e": KAPRODI_RSA_KEYS[current_user["major"]]["public"]["e"],
                        "n": KAPRODI_RSA_KEYS[current_user["major"]]["public"]["n"]
                },
                "created_at": academic["created_at"],
                "created_by_usn": academic["created_by_usn"]
        }

        return response_json