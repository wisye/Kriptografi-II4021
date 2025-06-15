# 🚀 SixNein! – Web App

**SixNein!** adalah aplikasi web modern dengan arsitektur **FastAPI (backend)** dan **Next.js (frontend)**. Proyek ini dirancang untuk memberikan pengalaman pengguna yang cepat, aman, dan responsif.

---

## 🧩 Project Structure

```
Tugas4/
├── backend/     ← FastAPI project
└── web/         ← Next.js frontend
```

---

## ✅ Deployment

-   Front-End: https://sixtynein.up.railway.app/
-   Back-End: https://sixtynein-backend-production.up.railway.app/

---

## ⚙️ Backend Setup (FastAPI)

1. **Masuk ke folder backend:**

    ```bash
    cd backend
    ```

2. **Buat dan aktifkan virtual environment:**

    ```bash
    python -m venv venv
    source venv/bin/activate      # macOS/Linux
    .\venv\Scripts\activate   # Windows
    ```

3. **Install dependencies:**

    ```bash
    pip install -r requirements.txt
    ```

4. **Ubah CORS Origins:**

    ```bash
     allow_origins=["{isi sendiri}"],

    ```

5. **Jalankan server FastAPI:**

    ```bash
    uvicorn app:app --reload
    ```

---

## 🌐 Frontend Setup (Next.js)

1. **Buka terminal baru dan masuk ke folder web:**

    ```bash
    cd web
    ```

2. **Install dependencies:**

    ```bash
    npm install
    ```

3. **tambah .env.local:**
    ```bash
    NEXT_PUBLIC_API_URL="{isi URL backend}"
    ```
4. **Jalankan project (development mode):**

    ```bash
    npm run dev
    ```

---

## 📦 Build for Production

Untuk membangun frontend secara production-ready:

```bash
npm run build
npm start
```

---

## 🛠 Teknologi yang Digunakan

-   🌐 **Frontend:** Next.js, Tailwind CSS, Framer Motion
-   🔧 **Backend:** FastAPI, Uvicorn
-   🔐 **Features:** AES Encryption, Shamir Secret Sharing, Secure File Handling

---
