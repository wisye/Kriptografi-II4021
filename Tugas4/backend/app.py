from fastapi import FastAPI, HTTPException, Depends, Query, Request, Response, File, UploadFile, Form
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
import random
import base64
from keys_config import KAPRODI_RSA_KEYS

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from io import BytesIO
from fastapi.responses import StreamingResponse
import os
from datetime import date

# 256+ bit prime 
P_SSSS = 115792089237316195423570985008687907853269984665640564039457584007913129640233
SSSS_THRESHOLD_K = 3
SSSS_NUM_SHARES_N = 6

app = FastAPI()
DATABASE = "database.db"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
sessions = {}

app.add_middleware(
        CORSMiddleware,
        allow_origins=["https://sixtynein.up.railway.app"],
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

class SSSShareInput(BaseModel):
        x: int
        y: str

class SSSReconstructionInput(BaseModel):
        shares: List[SSSShareInput]
        
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
        print("Initializing database...")
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users';")
        if cursor.fetchone() is None:
                with open("schema.sql", "r") as f:
                        conn.executescript(f.read())
                conn.commit()
             
                # Buat testing
                default_users = [
                        # Kaprodi
                        ("Kaprodi_IF", pwd_context.hash("qwe"), "Ketua Program Studi", "IF"),
                        ("Kaprodi_STI", pwd_context.hash("qwe"), "Ketua Program Studi", "STI"),

                        # Dosen Wali
                        ("Dosen_IF_1", pwd_context.hash("qwe"), "Dosen Wali", "IF"),
                        ("Dosen_IF_2", pwd_context.hash("qwe"), "Dosen Wali", "IF"),
                        ("Dosen_IF_3", pwd_context.hash("qwe"), "Dosen Wali", "IF"),
                        ("Dosen_IF_4", pwd_context.hash("qwe"), "Dosen Wali", "IF"),
                        ("Dosen_IF_5", pwd_context.hash("qwe"), "Dosen Wali", "IF"),
                        ("Dosen_IF_6", pwd_context.hash("qwe"), "Dosen Wali", "IF"),
                        ("Dosen_IF_7", pwd_context.hash("qwe"), "Dosen Wali", "IF"),

                        ("Dosen_STI_1", pwd_context.hash("qwe"), "Dosen Wali", "STI"),
                        ("Dosen_STI_2", pwd_context.hash("qwe"), "Dosen Wali", "STI"),
                        ("Dosen_STI_3", pwd_context.hash("qwe"), "Dosen Wali", "STI"),
                        ("Dosen_STI_4", pwd_context.hash("qwe"), "Dosen Wali", "STI"),
                        ("Dosen_STI_5", pwd_context.hash("qwe"), "Dosen Wali", "STI"),
                        ("Dosen_STI_6", pwd_context.hash("qwe"), "Dosen Wali", "STI"),
                        ("Dosen_STI_7", pwd_context.hash("qwe"), "Dosen Wali", "STI"),

                        # Mahasiswa
                        ("18222001", pwd_context.hash("qwe"), "Mahasiswa", "STI"),
                        ("18222002", pwd_context.hash("qwe"), "Mahasiswa", "STI"),
                        ("18222003", pwd_context.hash("qwe"), "Mahasiswa", "STI"),
                        ("18222004", pwd_context.hash("qwe"), "Mahasiswa", "STI"),
                        ("18222005", pwd_context.hash("qwe"), "Mahasiswa", "STI"),
                        ("18222006", pwd_context.hash("qwe"), "Mahasiswa", "STI"),
                        ("18222007", pwd_context.hash("qwe"), "Mahasiswa", "STI"),
                        ("18222008", pwd_context.hash("qwe"), "Mahasiswa", "STI"),
                        ("18222009", pwd_context.hash("qwe"), "Mahasiswa", "STI"),
                        ("18222010", pwd_context.hash("qwe"), "Mahasiswa", "STI"),
                        ("18222011", pwd_context.hash("qwe"), "Mahasiswa", "STI"),
                        ("18222012", pwd_context.hash("qwe"), "Mahasiswa", "STI"),
                        ("18222013", pwd_context.hash("qwe"), "Mahasiswa", "STI"),
                        ("18222014", pwd_context.hash("qwe"), "Mahasiswa", "STI"),
                        ("18222015", pwd_context.hash("qwe"), "Mahasiswa", "STI"),
                        ("18222016", pwd_context.hash("qwe"), "Mahasiswa", "STI"),
                        ("18222017", pwd_context.hash("qwe"), "Mahasiswa", "STI"),
                        ("18222018", pwd_context.hash("qwe"), "Mahasiswa", "STI"),
                        ("18222019", pwd_context.hash("qwe"), "Mahasiswa", "STI"),
                        ("18222020", pwd_context.hash("qwe"), "Mahasiswa", "STI"),
                        ("18222021", pwd_context.hash("qwe"), "Mahasiswa", "STI"),

                        ("13522001", pwd_context.hash("qwe"), "Mahasiswa", "IF"),
                        ("13522002", pwd_context.hash("qwe"), "Mahasiswa", "IF"),
                        ("13522003", pwd_context.hash("qwe"), "Mahasiswa", "IF"),
                        ("13522004", pwd_context.hash("qwe"), "Mahasiswa", "IF"),
                        ("13522005", pwd_context.hash("qwe"), "Mahasiswa", "IF"),
                        ("13522006", pwd_context.hash("qwe"), "Mahasiswa", "IF"),
                        ("13522007", pwd_context.hash("qwe"), "Mahasiswa", "IF"),
                        ("13522008", pwd_context.hash("qwe"), "Mahasiswa", "IF"),
                        ("13522009", pwd_context.hash("qwe"), "Mahasiswa", "IF"),
                        ("13522010", pwd_context.hash("qwe"), "Mahasiswa", "IF"),
                        ("13522011", pwd_context.hash("qwe"), "Mahasiswa", "IF"),
                        ("13522012", pwd_context.hash("qwe"), "Mahasiswa", "IF"),
                        ("13522013", pwd_context.hash("qwe"), "Mahasiswa", "IF"),
                        ("13522014", pwd_context.hash("qwe"), "Mahasiswa", "IF"),
                        ("13522015", pwd_context.hash("qwe"), "Mahasiswa", "IF"),
                        ("13522016", pwd_context.hash("qwe"), "Mahasiswa", "IF"),
                        ("13522017", pwd_context.hash("qwe"), "Mahasiswa", "IF"),
                        ("13522018", pwd_context.hash("qwe"), "Mahasiswa", "IF"),
                        ("13522019", pwd_context.hash("qwe"), "Mahasiswa", "IF"),
                        ("13522020", pwd_context.hash("qwe"), "Mahasiswa", "IF"),
                        ("13522021", pwd_context.hash("qwe"), "Mahasiswa", "IF"),
                ]
                cursor.executemany(
                        "INSERT INTO users (username, password, role, major) VALUES (?, ?, ?, ?)",
                        default_users
                )
                conn.commit()
                print("Database schema created successfully.")
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

def check_aes_hex(key_hex: str) -> bool:
        if len(key_hex) != 64:  # 32 bytes for AES-256
                return False
        try:
                bytes.fromhex(key_hex)
                return True
        except ValueError:
                return False
        
def hex_to_int(hex_str: str) -> int:
        try:
                return int(hex_str, 16)
        except ValueError:
                raise HTTPException(status_code=400, detail=f"Invalid hexadecimal string provided.")

def format_aes_key_as_hex_str(value: int) -> str: # For formatting an int that IS an AES key
    if value < 0:
        raise HTTPException(status_code=400, detail="AES key value must be non-negative")
    # 256-bit (32 bytes)
    return hex(value)[2:].zfill(64)

def general_int_to_hex_str(value: int) -> str:
    if value < 0:
        raise HTTPException(status_code=400, detail="Value must be non-negative for hex conversion")
    return hex(value)[2:]

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

def extended_gcd(a, b):
        if a == 0:
                return b, 0, 1
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y

def mod_inverse(a, m):
        d, x, y = extended_gcd(a, m)
        if d != 1:
                raise HTTPException(status_code=400, detail="Modular inverse does not exist")
        return (x % m + m) % m

def ssss_generate_shares(secret: int, n: int, k: int, prime: int, x_values: List[int]) -> List[Tuple[int, int]]:
        if k <= 1 or n < k:
                raise HTTPException(status_code=400, detail="Invalid parameters for Shamir's Secret Sharing")
        if secret >= prime:
                raise HTTPException(status_code=400, detail="Secret must be less than the prime modulus")
        if len(x_values) != n:
                raise HTTPException(status_code=400, detail="Number of x_values must match n")
        if not all(0 < x < prime for x in x_values):
                raise HTTPException(status_code=400, detail="All x_values must be in the range (0, prime)")
        if len(set(x_values)) != n:
                raise HTTPException(status_code=400, detail="x_values must be unique")
        
        coefficients = [secret] + [random.randint(0, prime - 1) for _ in range(k - 1)]
        
        shares = []
        for x in x_values:
                y = 0
                for power, coeff in enumerate(coefficients):
                        # coeff * (x ** power) % prime
                        current_x_power = 1
                        for _ in range(power):
                                current_x_power = (current_x_power * x) % prime
                        term = (coeff * current_x_power) % prime
                        y = (y + term) % prime
                shares.append((x, y))
        return shares

def ssss_reconstruct_secret(shares: List[Tuple[int, int]], prime: int) -> int:
        if len(shares) < 2:
                raise HTTPException(status_code=400, detail="At least two shares are required to reconstruct the secret")
        if not all(0 < x < prime for x, _ in shares):
                raise HTTPException(status_code=400, detail="All x_values in shares must be in the range (0, prime)")
        if len(set(x for x, _ in shares)) != len(shares):
                raise HTTPException(status_code=400, detail="x_values in shares must be unique")

        secret = 0
        for i, (x_i, y_i) in enumerate(shares):
                numerator = 1
                denominator = 1
                for j, (x_j, _) in enumerate(shares):
                        if i != j:
                                numerator = (numerator * (-x_j)) % prime
                                denominator = (denominator * (x_i - x_j)) % prime
                denominator_inv = mod_inverse(denominator, prime)
                term = (y_i * numerator * denominator_inv) % prime
                secret = (secret + term) % prime    
        return secret    

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

@app.get("/user/list_maba")
def list_maba(
    db: sqlite3.Connection = Depends(get_db),
    current_user=Depends(require_role(["Dosen Wali"]))
):
    cursor = db.cursor()

    # Secure parameterized SQL
    query = "SELECT u.username, u.major FROM users u LEFT JOIN academics a ON u.username = a.nim WHERE u.role = 'Mahasiswa' AND u.major = ? AND a.nim IS NULL"
    cursor.execute(query, (current_user["major"],))
    maba_list = cursor.fetchall()

    return {"maba_list": [dict(row) for row in maba_list]}


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
        checked = check_aes_hex(academic_data.aes_key_hex)
        if not checked:
                raise HTTPException(status_code=400, detail="AES key must be 64 hexadecimal characters (32 bytes)")                      

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
        
        # Mahasiswa's major is used to determine the RSA keys
        cursor = db.cursor()
        cursor.execute("SELECT major FROM users WHERE username = ?", (academic_data.nim,))
        major_row = cursor.fetchone()
        if not major_row:
                raise HTTPException(status_code=404, detail="Mahasiswa not found")
        major = major_row["major"]
        public_key = KAPRODI_RSA_KEYS[major]["public"]

        try:
                aes_key_int = hex_to_int(academic_data.aes_key_hex)
                encrypted_aes_key_int = rsa_encrypt(aes_key_int, (public_key["e"], public_key["n"]))
                encrypted_aes_key_hex = general_int_to_hex_str(encrypted_aes_key_int)
        except Exception as e:
                raise HTTPException(status_code=500, detail=f"RSA Encryption error: {str(e)}")

        # Hash academic data
        try:
                hashed_data = hashlib.sha3_256(data_json.encode()).hexdigest()
        except Exception as e:
                raise HTTPException(status_code=500, detail=f"Hashing error: {str(e)}")

        # Sign hash with RSA private key
        try:
                hashed_data_int = hex_to_int(hashed_data)
                private_key = KAPRODI_RSA_KEYS[major]["private"]
                signature_int = rsa_encrypt(hashed_data_int, (private_key["d"], private_key["n"]))
                signature_hex = general_int_to_hex_str(signature_int)
        except ValueError as e:
                raise HTTPException(status_code=400, detail=f"Invalid hash format: {str(e)}")
    
        # Store academic in database
        try:
                cursor = db.cursor()
                cursor.execute(
                        "INSERT INTO academics (nim, name, encrypted_data, encrypted_key, hashed_data, signature, created_by) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (academic_data.nim, academic_data.name, encrypted_data, encrypted_aes_key_hex, hashed_data, signature_hex, current_user["id"])
                )
                academic_id = cursor.lastrowid
                db.commit()
        except sqlite3.Error as e:
                raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    
        return {
                "message": "academic saved successfully",
                "academic_id": academic_id,
                "ipk": ipk,
                "signature": signature_hex
        }

@app.get("/academic/list")
def list_academics(
        db: sqlite3.Connection = Depends(get_db),
        current_user = Depends(get_current_user)
):
        cursor = db.cursor()

        base_query = "SELECT t.id, t.nim, t.name, t.created_at, u.username AS created_by_usn FROM academics t JOIN users u ON t.created_by = u.id"
        print("current_user role:", current_user["role"])
        try:
                if current_user["role"] == "Mahasiswa":
                        # Students can only see their own academic
                        cursor.execute(f"{base_query} WHERE t.nim = ?", (current_user["username"],))
                elif current_user["role"] == "Dosen Wali" or current_user["role"] == "Ketua Program Studi":
                        # Dosen Wali and Ketua Program Studi can list all academics
                        if current_user["major"] == "STI":
                                base_query += " WHERE t.nim LIKE '1822%'"
                                cursor.execute(f"{base_query}")
                        elif current_user["major"] == "IF":
                                base_query += " WHERE t.nim LIKE '1352%'"
                                cursor.execute(f"{base_query}")
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
                
        academic = dict(academic)
        
        if current_user["role"] == "Mahasiswa":
                # Students can only view their own academic
                if academic["nim"] != current_user["username"]:
                        raise HTTPException(status_code=403, detail="You do not have permission to view this academic")
                # If aes_key_hex is provided, use it for decryption
                checked = check_aes_hex(aes_key_hex)
                if not checked:
                        raise HTTPException(status_code=400, detail="AES key must be 64 hexadecimal characters (32 bytes)")
                academic["aes_key_hex"] = aes_key_hex

        if current_user["role"] == "Dosen Wali":
                if academic["created_by_usn"] != current_user["username"]:
                        raise HTTPException(status_code=403, detail="You do not have permission to view this academic's AES key. Please refer to SSS")

                # Decrypt AES key using private RSA key
                major = current_user["major"]
                if major not in KAPRODI_RSA_KEYS:
                        raise HTTPException(status_code=400, detail="Invalid major for decryption keys")
                private_key = KAPRODI_RSA_KEYS[major]["private"]
                try:
                        encrypted_aes_key_int = hex_to_int(academic["encrypted_key"])
                        decrypted_aes_key_int = rsa_decrypt(encrypted_aes_key_int, (private_key["d"], private_key["n"]))
                        decrypted_aes_key_hex = format_aes_key_as_hex_str(decrypted_aes_key_int)
                        academic["aes_key_hex"] = decrypted_aes_key_hex
                except Exception as e:
                        raise HTTPException(status_code=500, detail=f"Decrypting AES key error: {str(e)}")
        
        elif current_user["role"] == "Ketua Program Studi":
                # Decrypt AES key using private RSA key
                major = current_user["major"]
                if major not in KAPRODI_RSA_KEYS:
                        raise HTTPException(status_code=400, detail="Invalid major for decryption keys")
                private_key = KAPRODI_RSA_KEYS[major]["private"]
                try:
                        encrypted_aes_key_int = hex_to_int(academic["encrypted_key"])
                        decrypted_aes_key_int = rsa_decrypt(encrypted_aes_key_int, (private_key["d"], private_key["n"]))
                        decrypted_aes_key_hex = format_aes_key_as_hex_str(decrypted_aes_key_int)
                        academic["aes_key_hex"] = decrypted_aes_key_hex
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
                
        e = KAPRODI_RSA_KEYS[current_user['major']]['public']['e'] 
        n = KAPRODI_RSA_KEYS[current_user['major']]['public']['n'] 

        response_json = {
                "id": academic["id"],
                "nim": decrypted_json["nim"],
                "name": decrypted_json["name"],
                "courses": decrypted_json["courses"],
                "ipk": decrypted_json["ipk"],
                "hashed_data": academic["hashed_data"],
                "signature": academic["signature"],
                "kaprodi_public_key": {
                        "e": str(e),
                        "n": str(n) if n is not None else None
                },
                "created_at": academic["created_at"],
                "created_by_usn": academic["created_by_usn"]
        }

        return response_json

@app.post("/academic/{academic_id}/view-sss") # membuat AES Key dari 3 input sec
def get_academic_detail_with_sss( 
        # kalau udah request, nunggu 3 part of secret shared keys
        # udah termasuk rekonstruksi AES key
        # return akademik 
        academic_id: int,
        reconstruction_input: SSSReconstructionInput, 
        db: sqlite3.Connection = Depends(get_db),
        current_user = Depends(require_role(["Dosen Wali"])) 
):
        cursor = db.cursor()
        cursor.execute(
                """SELECT t.id, t.nim, t.name, t.encrypted_data, t.encrypted_key, 
                        t.hashed_data, t.signature, t.created_at, 
                        u.username AS created_by_usn, t.created_by AS creator_id 
                FROM academics t 
                JOIN users u ON t.created_by = u.id 
                WHERE t.id = ?""",
                (academic_id,)
        )       
        academic_row = cursor.fetchone()

        if not academic_row:
                raise HTTPException(status_code=404, detail="Academic record not found")
                
        academic = dict(academic_row)
        creator_id = academic["creator_id"]
        decrypted_aes_key_to_use: Optional[str] = None

        # SSS Reconstruction logic
        if not reconstruction_input or not reconstruction_input.shares:
                raise HTTPException(status_code=400, detail="SSS shares must be provided for reconstruction.")

        # Check if the creator's share is provided
        creator_share_provided = False
        for share in reconstruction_input.shares:
                if share.x == creator_id:
                        creator_share_provided = True
                        break
        if not creator_share_provided:
                cursor.execute("SELECT username FROM users WHERE id = ?", (creator_id,))
                creator_user_row = cursor.fetchone()
                creator_username = creator_user_row["username"] if creator_user_row else "Unknown Creator"
                raise HTTPException(status_code=400, detail=f"Creator's share is required for SSS reconstruction. Creator: {creator_username}")

        cursor.execute(
                "SELECT prime, threshold FROM shamir_shares WHERE academic_id = ? LIMIT 1",
                (academic_id,)
        )
        share_params_row = cursor.fetchone()

        if not share_params_row:
                raise HTTPException(status_code=404, detail="SSS parameters not found for this academic record. Cannot reconstruct.")
        
        prime_ssss_str = share_params_row["prime"]
        threshold_ssss = share_params_row["threshold"]
        
        try:
                prime_ssss_int = int(prime_ssss_str)
                # print(f"DEBUG: academic_id={academic_id}, Fetched prime_ssss_str from DB: '{prime_ssss_str}'") # ADD THIS
                # print(f"DEBUG: Converted prime_ssss_int: {prime_ssss_int}")
                # print(f"DEBUG: Global P_SSSS: {P_SSSS}") 
        except ValueError:
                raise HTTPException(status_code=500, detail="Invalid prime stored for SSS.")

        if len(reconstruction_input.shares) < threshold_ssss:
                raise HTTPException(status_code=400, detail=f"Insufficient shares provided for SSS. Need {threshold_ssss}, got {len(reconstruction_input.shares)}.")

        prepared_shares_for_ssss: List[Tuple[int, int]] = []
        for s_in in reconstruction_input.shares: 
                try:
                        share_y_int = hex_to_int(s_in.y) # Use s_in.y as per your model
                        # Validate x value (s_in.x) against prime
                        if not (0 < s_in.x < prime_ssss_int): 
                                raise ValueError(f"Share x-value {s_in.x} is out of valid range for prime.")
                        prepared_shares_for_ssss.append((s_in.x, share_y_int)) # Use s_in.x
                except ValueError as ve:
                        raise HTTPException(status_code=400, detail=f"Invalid share format for x={s_in.x}: {str(ve)}")
                except HTTPException as he: 
                        raise he
        
        try:
                reconstructed_aes_key_int = ssss_reconstruct_secret(prepared_shares_for_ssss, prime_ssss_int)
                print(f"DEBUG: Reconstructed AES key (int): {reconstructed_aes_key_int}")
                decrypted_aes_key_to_use = format_aes_key_as_hex_str(reconstructed_aes_key_int)
                print(f"DEBUG: Reconstructed AES key (hex): {decrypted_aes_key_to_use}") 
        except HTTPException as he_reconstruct:
                raise he_reconstruct 
        except Exception as e_reconstruct:
                print(f"Unexpected SSS Key reconstruction error: {e_reconstruct}")
                raise HTTPException(status_code=500, detail=f"SSS Key reconstruction failed: {str(e_reconstruct)}")

        # Decrypt academic data if key is available
        decrypted_json_content = None
        if decrypted_aes_key_to_use:
                try:
                        decrypted_data_str = decrypt_aes_cbc(academic["encrypted_data"], decrypted_aes_key_to_use)
                        decrypted_json_content = json.loads(decrypted_data_str)
                except ValueError as e_decrypt:
                        print(f"AES Decryption or JSON parsing error for academic_id {academic_id}: {str(e_decrypt)}")
                        decrypted_json_content = {"error_decrypting": f"AES Decryption/JSON parsing failed: {str(e_decrypt)}"}
                except Exception as e_decrypt_unexpected:
                        print(f"Unexpected error during academic decryption for academic_id {academic_id}: {str(e_decrypt_unexpected)}")
                        decrypted_json_content = {"error_decrypting": f"Unexpected decryption error: {str(e_decrypt_unexpected)}"}
        else:
                decrypted_json_content = {"error_decrypting": "AES key reconstruction failed or key not obtained."}
                
        # Prepare response
        cursor.execute("SELECT major FROM users WHERE username = ?", (academic["nim"],))
        student_user_row_for_key = cursor.fetchone()
        student_major_for_kaprodi_key = student_user_row_for_key["major"] if student_user_row_for_key else None

        kaprodi_public_key_for_response = None
        if student_major_for_kaprodi_key and student_major_for_kaprodi_key in KAPRODI_RSA_KEYS:
                pub_key_obj = KAPRODI_RSA_KEYS[student_major_for_kaprodi_key]['public']
                kaprodi_public_key_for_response = {
                "e": str(pub_key_obj['e']),
                "n": str(pub_key_obj['n']) if pub_key_obj['n'] is not None else None
                }

        response_payload = {
                "id": academic["id"],
                "nim": decrypted_json_content.get("nim") if decrypted_json_content and "error_decrypting" not in decrypted_json_content else academic["nim"],
                "name": decrypted_json_content.get("name") if decrypted_json_content and "error_decrypting" not in decrypted_json_content else academic.get("name", "N/A"),
                "courses": decrypted_json_content.get("courses") if decrypted_json_content and "error_decrypting" not in decrypted_json_content else None,
                "ipk": decrypted_json_content.get("ipk") if decrypted_json_content and "error_decrypting" not in decrypted_json_content else None,
                "hashed_data": academic.get("hashed_data"),
                "signature": academic.get("signature"),
                "kaprodi_public_key": kaprodi_public_key_for_response,
                "created_at": academic.get("created_at"),
                "created_by_usn": academic.get("created_by_usn"),
                "decryption_status": "success" if decrypted_json_content and "error_decrypting" not in decrypted_json_content else "failed"
        }
        
 
        if decrypted_json_content and "error_decrypting" in decrypted_json_content:
                response_payload["decryption_error_detail"] = decrypted_json_content["error_decrypting"]
        return response_payload

def generate_pdf(academic_data):
        buffer = BytesIO()
        doc = SimpleDocTemplate(
                buffer,
                pagesize=letter,
                rightMargin=72,
                leftMargin=72,
                topMargin=72,
                bottomMargin=72
        )
        
        elements = []
        
        styles = getSampleStyleSheet()
        title_style = styles['Heading1']
        subtitle_style = styles['Heading2']
        normal_style = styles['Normal']
        
        elements.append(Paragraph("Institut Teknologi Berlin", title_style))
        elements.append(Spacer(1, 0.25 * inch))
        
        nim = academic_data['nim']
        jurusan = ""
        kaprodi = ""
        if nim and len(nim) >= 3:
                first_three_digits = nim[:3]
                if first_three_digits == "135":
                        jurusan = "Informatika"
                        kaprodi = "Yudistira Dwi Wardhana Asnar, S.T., Ph.D."
                else:
                        jurusan = "Sistem dan Teknologi Informasi"
                        kaprodi = "Ir. I Gusti Bagus Baskara Nugraha, S.T., M.T., Ph.D."
        
        elements.append(Paragraph(f"Nama: {academic_data['name']}", subtitle_style))
        elements.append(Paragraph(f"NIM: {academic_data['nim']}", subtitle_style))
        elements.append(Paragraph(f"Jurusan: {jurusan}", subtitle_style))
        elements.append(Paragraph(f"Tanggal: {date.today().strftime('%B %d, %Y')}", normal_style))
        elements.append(Paragraph(f"IPK: {academic_data['ipk']}", subtitle_style))
        elements.append(Paragraph(f"Dosen Wali: {academic_data['created_by_usn']}", normal_style))
        elements.append(Spacer(1, 0.5 * inch))
        
        data = [
                ['Course Code', 'Course Name', 'Credits', 'Grade']
        ]
        
        for course in academic_data['courses']:
                data.append([
                course['course_code'],
                course['course_name'],
                str(course['credits']),
                str(course['grade'])
                ])
        
        total_credits = sum(course['credits'] for course in academic_data['courses'])
        data.append(['Total', '', str(total_credits), ''])
        
        table = Table(data, colWidths=[1 * inch, 3 * inch, 1 * inch, 1 * inch])
        
        table_style = TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, -1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ])
        
        for i in range(1, len(data) - 1):
                if i % 2 == 0:
                        table_style.add('BACKGROUND', (0, i), (-1, i), colors.lightgrey)
        
        table.setStyle(table_style)
        elements.append(table)
        
        elements.append(Spacer(1, 1 * inch))
        elements.append(Paragraph("Digital Signature: " + academic_data['signature'][:20] + "...", normal_style))
        elements.append(Spacer(1, 0.5 * inch))
        elements.append(Paragraph(f"Ketua Program Studi: {kaprodi}", normal_style))
        
        doc.build(elements)
        buffer.seek(0)
        return buffer

@app.get("/academic/{academic_id}/pdf")
def get_academic_pdf(
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
                raise HTTPException(status_code=404, detail="Academic record not found")
        
        if current_user["role"] == "Mahasiswa" and academic["nim"] != current_user["username"]:
                raise HTTPException(status_code=403, detail="You can only view your own academic records")
        
        academic = dict(academic)

        if current_user["role"] in ["Dosen Wali", "Ketua Program Studi"]:
                if isinstance(current_user, sqlite3.Row):
                        current_user = dict(current_user)
                major = current_user.get("major")
                if not major or major not in KAPRODI_RSA_KEYS:
                        raise HTTPException(status_code=400, detail="Invalid major for decryption keys")
                private_key = KAPRODI_RSA_KEYS[major]["private"]
                try:
                        encrypted_aes_key = hex_to_int(academic["encrypted_key"])
                        decrypted_aes_key = rsa_decrypt(encrypted_aes_key, (private_key["d"], private_key["n"]))
                        academic["aes_key_hex"] = format_aes_key_as_hex_str(decrypted_aes_key)
                except Exception as e:
                        raise HTTPException(status_code=500, detail=f"Decrypting AES key error: {str(e)}")
        elif current_user["role"] == "Mahasiswa" and academic["nim"] == current_user["username"]:
                academic["aes_key_hex"] = aes_key_hex
        else:
                raise HTTPException(status_code=403, detail="You do not have permission to view this academic's AES key")

        try:
                decrypted_data = decrypt_aes_cbc(academic["encrypted_data"], academic["aes_key_hex"])
                decrypted_json = json.loads(decrypted_data)
        except ValueError as e:
                raise HTTPException(status_code=400, detail=f"Academic's AES Decryption error: {str(e)}")
        except Exception as e:
                raise HTTPException(status_code=500, detail=f"Unexpected error during academic decryption: {str(e)}")
        
        academic_data = {
                "id": academic["id"],
                "nim": decrypted_json["nim"],
                "name": decrypted_json["name"],
                "courses": decrypted_json["courses"],
                "ipk": decrypted_json["ipk"],
                "signature": academic["signature"],
                "created_at": academic["created_at"],
                "created_by_usn": academic["created_by_usn"]
        }
        
        pdf_buffer = generate_pdf(academic_data)
        
        filename = f"transcript_{academic_data['nim']}_{date.today().strftime('%Y%m%d')}.pdf"
        headers = {
                'Content-Disposition': f'attachment; filename="{filename}"'
        }
        
        return StreamingResponse(
                pdf_buffer, 
                media_type="application/pdf",
                headers=headers
        )
        
def rc4_ksa(key):
        key_bytes = key.encode() if isinstance(key, str) else key
        S = list(range(256))
        j = 0
        for i in range(256):
                j = (j + S[i] + key_bytes[i % len(key_bytes)]) % 256
                S[i], S[j] = S[j], S[i]
        return S

def rc4_prga(S, data):
        i = j = 0
        encrypted = bytearray()
        for byte in data:
                i = (i + 1) % 256
                j = (j + S[i]) % 256
                S[i], S[j] = S[j], S[i]
                k = S[(S[i] + S[j]) % 256]
                encrypted.append(byte ^ k)
        return bytes(encrypted)

def rc4_encrypt(data, key):
        if isinstance(data, str):
                data = data.encode()
        S = rc4_ksa(key)
        return rc4_prga(S, data)

def rc4_decrypt(encrypted_data, key):
        return rc4_encrypt(encrypted_data, key)

@app.get("/academic/{academic_id}/encrypted-pdf")
def get_encrypted_academic_pdf(
        academic_id: int,
        rc4_key: str,
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
                raise HTTPException(status_code=404, detail="Academic record not found")
        
        if current_user["role"] == "Mahasiswa" and academic["nim"] != current_user["username"]:
                raise HTTPException(status_code=403, detail="You can only view your own academic records")
        
        academic = dict(academic)
        if current_user["role"] == "Ketua Program Studi" or current_user["role"] == "Dosen Wali":
                major = current_user["major"]
                if major not in KAPRODI_RSA_KEYS:
                        raise HTTPException(status_code=400, detail="Invalid major for decryption keys")
                private_key = KAPRODI_RSA_KEYS[major]["private"]
                try:
                        encrypted_aes_key = hex_to_int(academic["encrypted_key"])
                        decrypted_aes_key = rsa_decrypt(encrypted_aes_key, (private_key["d"], private_key["n"]))
                        academic["aes_key_hex"] = format_aes_key_as_hex_str(decrypted_aes_key)
                except Exception as e:
                        raise HTTPException(status_code=500, detail=f"Decrypting AES key error: {str(e)}")
        elif current_user["role"] == "Mahasiswa" and academic["nim"] == current_user["username"]:
                academic["aes_key_hex"] = aes_key_hex

        try:
                decrypted_data = decrypt_aes_cbc(academic["encrypted_data"], academic["aes_key_hex"])
                decrypted_json = json.loads(decrypted_data)
        except ValueError as e:
                raise HTTPException(status_code=400, detail=f"Academic's AES Decryption error: {str(e)}")
        except Exception as e:
                raise HTTPException(status_code=500, detail=f"Unexpected error during academic decryption: {str(e)}")
        
        academic_data = {
                "id": academic["id"],
                "nim": decrypted_json["nim"],
                "name": decrypted_json["name"],
                "courses": decrypted_json["courses"],
                "ipk": decrypted_json["ipk"],
                "signature": academic["signature"],
                "created_at": academic["created_at"],
                "created_by_usn": academic["created_by_usn"]
        }
        
        pdf_buffer = generate_pdf(academic_data)
        
        pdf_content = pdf_buffer.getvalue()
        
        encrypted_content = rc4_encrypt(pdf_content, rc4_key)
        
        filename = f"encrypted_transcript_{academic_data['nim']}_{date.today().strftime('%Y%m%d')}.pdf.enc"
        headers = {
                'Content-Disposition': f'attachment; filename="{filename}"'
        }
        
        return Response(
                content=encrypted_content,
                media_type="application/octet-stream",
                headers=headers
        )

@app.post("/decrypt-rc4")
async def decrypt_rc4_file(
    file: UploadFile = File(...),
    rc4_key: str = Form(...),
    current_user = Depends(get_current_user)
):
        encrypted_content = await file.read()
        
        try:
                decrypted_content = rc4_decrypt(encrypted_content, rc4_key)
        except Exception as e:
                raise HTTPException(status_code=400, detail=f"Decryption error: {str(e)}")
        
        original_filename = file.filename
        if original_filename.endswith('.enc'):
                original_filename = original_filename[:-4]
        
        headers = {
                'Content-Disposition': f'attachment; filename="{original_filename}"'
        }
        
        return Response(
                content=decrypted_content,
                media_type="application/pdf" if original_filename.endswith('.pdf') else "application/octet-stream",
                headers=headers
        )

@app.get("/shamir/my_splits")
def list_shamir_splits(
        db: sqlite3.Connection = Depends(get_db),
        current_user = Depends(require_role(["Dosen Wali"]))
):
        cursor = db.cursor()
        cursor.execute(
                """SELECT ss.id, ss.academic_id, a.nim as student_nim, a.name as student_name, 
                        ss.share_x, ss.share_y, ss.prime, ss.threshold, ss.requested_by, ss.created_at 
                FROM shamir_shares ss
                JOIN academics a ON ss.academic_id = a.id
                WHERE ss.dosen_wali_id = ?""", 
                (current_user["id"],)
        )
        splits = cursor.fetchall()
        
        return {"splits": [dict(split) for split in splits]}

@app.post("/shamir/request_split/{academic_id}")
def request_shamir_split(
        # split AES key for sharing with other Dosen Wali (3 - 6 shares)
        # input to shamir_shares relation
        academic_id: int,
        db: sqlite3.Connection = Depends(get_db),
        current_user = Depends(require_role(["Dosen Wali"]))
):
        cursor = db.cursor()
        
        cursor.execute("SELECT * FROM academics WHERE id = ?", (academic_id,))
        academic = cursor.fetchone()
        if not academic:
                raise HTTPException(status_code=404, detail="Academic record not found")
        
        # Retrieve student's major
        cursor.execute("SELECT major FROM users WHERE username = ?", (academic["nim"],))
        student_info = cursor.fetchone()
        if not student_info:
                raise HTTPException(status_code=404, detail=f"Student with NIM {academic['nim']} not found")
        student_major = student_info["major"]

        if student_major not in KAPRODI_RSA_KEYS:
                raise HTTPException(status_code=400, detail=f"RSA keys not configured for student's major: {student_major}")
        
        private_key_for_aes_decryption = KAPRODI_RSA_KEYS[student_major]["private"]
        aes_key_hex_str_for_sharing: str
        try:
                encrypted_aes_key_int = hex_to_int(academic["encrypted_key"])
                decrypted_aes_key_int = rsa_decrypt(encrypted_aes_key_int, (private_key_for_aes_decryption["d"], private_key_for_aes_decryption["n"]))
                aes_key_hex_str_for_sharing = format_aes_key_as_hex_str(decrypted_aes_key_int) # USE CORRECT FORMATTER
        except Exception as e:
                print(f"Error decrypting AES key for SSS request (academic_id: {academic_id}): {str(e)}")
                raise HTTPException(status_code=500, detail=f"Failed to retrieve or decrypt the AES key for sharing. Error: {str(e)}")

        aes_key_int_for_ssss = hex_to_int(aes_key_hex_str_for_sharing)
        if aes_key_int_for_ssss >= P_SSSS: 
            raise HTTPException(status_code=400, detail="AES key (as integer) is too large for SSSS with the chosen prime.")

        # Selected dosen wali: requester, mahasiswa's dosen wali, and 4 other dosen wali
        # Assumption: the same major only
        requester_id = current_user["id"]
        creator_id = academic["created_by"]
        selected_dosen_ids = set([requester_id, creator_id]) 
        num_other_dosen_needed = SSSS_NUM_SHARES_N - len(selected_dosen_ids)

        cursor.execute(
                f"SELECT id FROM users WHERE role = 'Dosen Wali' AND major = ? AND id NOT IN ({','.join('?' for _ in selected_dosen_ids)})",
                (student_major, *selected_dosen_ids)
        )
        other_dosen_wali_rows = cursor.fetchall()
        
        if len(other_dosen_wali_rows) < num_other_dosen_needed:
            raise HTTPException(
                status_code=400, 
                detail=f"Not enough other Dosen Wali to generate {SSSS_NUM_SHARES_N} shares. "
                       f"Need {num_other_dosen_needed} others, found {len(other_dosen_wali_rows)}."
            )

        selected_other_dosen_ids = [dw["id"] for dw in random.sample(other_dosen_wali_rows, num_other_dosen_needed)]
        selected_dosen_ids.update(selected_other_dosen_ids)

        dosen_wali_ids_as_x_values = list(selected_dosen_ids)
        if len(set(dosen_wali_ids_as_x_values)) != SSSS_NUM_SHARES_N:
            raise HTTPException(status_code=500, detail="Failed to select a unique set of Dosen Wali for shares.")
        
        shares_generated_tuples: List[Tuple[int, int]]
        try:
            shares_generated_tuples = ssss_generate_shares(
                    secret=aes_key_int_for_ssss,
                    n=SSSS_NUM_SHARES_N,
                    k=SSSS_THRESHOLD_K,
                    prime=P_SSSS,
                    x_values=dosen_wali_ids_as_x_values # DOSEN WALI IDs AS X_VALUES
            )
        except HTTPException as he: 
            raise he 
        except Exception as e: 
            print(f"Unexpected error during ssss_generate_shares for academic_id {academic_id}: {str(e)}")
            raise HTTPException(status_code=500, detail=f"Error generating SSS shares: {str(e)}")

        # Requester shares
        my_share_details_for_response = None
        try:
            for x_coordinate_dosen_id, y_coordinate_as_int in shares_generated_tuples:
                share_y_as_hex = general_int_to_hex_str(y_coordinate_as_int) 
                
                cursor.execute(
                        """INSERT INTO shamir_shares 
                           (academic_id, dosen_wali_id, prime, threshold, share_x, share_y, requested_by) 
                           VALUES (?, ?, ?, ?, ?, ?, ?)""",
                        (academic_id, x_coordinate_dosen_id, str(P_SSSS), SSSS_THRESHOLD_K, x_coordinate_dosen_id, share_y_as_hex, current_user["username"])
                )
                if x_coordinate_dosen_id == current_user["id"]:
                    my_share_details_for_response = {"share_x": x_coordinate_dosen_id, "share_y_hex": share_y_as_hex}
            db.commit()
        except sqlite3.Error as e:
            db.rollback() 
            raise HTTPException(status_code=500, detail=f"Database error inserting SSS shares: {str(e)}")
        
        # Username of other receiving Dosen Wali
        cursor.execute(
                "SELECT username FROM users WHERE id IN ({})".format(','.join('?' for _ in dosen_wali_ids_as_x_values)),
                dosen_wali_ids_as_x_values
        )
        dosen_wali_usernames = cursor.fetchall()
        receiving_dosen_wali_usernames = [row["username"] for row in dosen_wali_usernames]

        # Username of mahasiswa's Dosen Wali
        cursor.execute(
                "SELECT username FROM users WHERE id = ?",
                (creator_id,)
        )
        mahasiswa_dosen_wali_username_row = cursor.fetchone()
        mahasiswa_dosen_wali_username = mahasiswa_dosen_wali_username_row["username"] if mahasiswa_dosen_wali_username_row else None


        return {
            "message": "Shamir's Secret Sharing split created successfully", 
            "my_share": my_share_details_for_response, 
            "academic_id": academic_id,
            "receiving_dosen_wali_usernames": receiving_dosen_wali_usernames,
            "mahasiswa_dosen_wali_username": mahasiswa_dosen_wali_username,
        }