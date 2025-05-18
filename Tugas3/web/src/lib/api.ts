// src/lib/api.ts
import axios from "axios";

const api = axios.create({
  baseURL: "http://localhost:8000",
  withCredentials: true, // agar session_token (cookie) ikut terkirim
});

export default api;
