// src/lib/api.ts
import axios from "axios";

const api = axios.create({
  baseURL: "http://localhost:8000/", // dev
  // baseURL: "http://103.59.160.119:4021", // prod
  withCredentials: true, 
});

export default api;
