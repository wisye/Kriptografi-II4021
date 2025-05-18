"use client";

import { useState } from "react";
import axios from "axios";
import { sha3_256 } from "js-sha3";
import { secp256k1 } from "@noble/curves/secp256k1";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import Link from "next/link";

const bytesToHex = (bytes: Uint8Array) =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

export default function RegisterPage() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const handleRegister = async () => {
    setError(null);
    setSuccess(null);
    if (!username.trim() || !password.trim()) {
      setError("Username dan password wajib diisi.");
      return;
    }
    setLoading(true);
    try {

      const privKeyBytes = secp256k1.utils.randomPrivateKey();   // 32 bytes
      const pubKeyBytes  = secp256k1.getPublicKey(privKeyBytes); // 65 bytes (04||X||Y)

      const privHex = bytesToHex(privKeyBytes);                 // simpan ke localStorage
      const xHex   = bytesToHex(pubKeyBytes.slice(1, 33));      // potong header 0x04
      const yHex   = bytesToHex(pubKeyBytes.slice(33, 65));

      localStorage.setItem("privateKey", privHex);

      /* 2️⃣  Hash password dengan SHA-3 ----------------------- */
      const pwdHash = sha3_256(password);

      /* 3️⃣  POST ke /api/register ---------------------------- */
      await axios.post("http://localhost:8000/api/register", {
        username,
        password: pwdHash,          // server tetap meng-hash ulang dgn bcrypt
        public_key_x: "0x" + xHex,
        public_key_y: "0x" + yHex,
      });

      setSuccess("Registrasi berhasil! Silakan login.");
      setUsername("");
      setPassword("");
    } catch (e: any) {
      setError(
        e.response?.data?.detail ??
          "Registrasi gagal, periksa kembali isian Anda."
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex items-center justify-center min-h-screen bg-gradient-to-tr from-blue-500 to-rose-500 p-6">
      <Card className="w-full rounded-xl max-w-md shadow-rose-500/20 shadow-xl">
        <CardHeader>
          <CardTitle className="flex items-center font-bold text-blue-600 justify-center text-3xl">
            Register
          </CardTitle>
        </CardHeader>

        <CardContent className="flex flex-col gap-4">
          <Input
            placeholder="Username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
          <Input
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />

          <Button onClick={handleRegister} disabled={loading}>
            {loading ? "Processing…" : "Register"}
          </Button>

          {error && <p className="text-red-600 text-sm">{error}</p>}
          {success && <p className="text-green-600 text-sm">{success}</p>}

          <h3>
            Already have an account?{" "}
            <Link href="/login" className="text-blue-600 hover:underline">
              Login
            </Link>
          </h3>
        </CardContent>
      </Card>
    </div>
  );
}
