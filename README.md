# Secure Chatroom

1. **Stack** | Next.js (client) + FastAPI (server)
2. **Security** | Each message is SHA‑3 hashed and ECDSA‑signed for end‑to‑end integrity.
3. **Transport & Storage** | Real‑time via WebSocket, persisted in SQLite.
5. **Install**
   change Port first into localhost
   ```bash
   npm install                      # front-end deps
   npm run dev
   pip install -r requirements.txt  # back-end deps
   uvicorn app:app --reload
