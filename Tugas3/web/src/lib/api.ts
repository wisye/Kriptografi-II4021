// src/lib/api.ts
import axios from "axios";

const api = axios.create({
  baseURL: "http://103.59.160.119:3000/",
  withCredentials: true, // agar session_token (cookie) ikut terkirim
});

export default api;
