"use client";

import { useState } from "react";
import axios from "axios";
import { sha3_256 } from "js-sha3";
import { ec as EC } from "elliptic";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import Link from "next/link";

const ec = new EC("secp256k1");

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
      
      const key = ec.genKeyPair();
      const privHex = key.getPrivate("hex");
      const pub = key.getPublic(); // x dan yisinya
      console.log(privHex);
      console.log(pub);

      const xHex = pub.getX().toString("hex").padStart(64, "0");
      const yHex = pub.getY().toString("hex").padStart(64, "0");
      console.log(xHex);
      console.log(yHex);

      localStorage.setItem("privateKey", privHex); // ini di devTools > applications > localStorage

      const pwdHash = sha3_256(password);

      await axios.post("http://localhost:8000/api/register", { // POST request
        username,
        password: pwdHash,
        public_key_x: "0x" + xHex,
        public_key_y: "0x" + yHex,
      });

      setSuccess("Your new account has been registered. Please login!");
      setUsername("");
      setPassword("");
    } catch (err: any) {
      setError(
        err.response?.data?.detail ??
          "Error! Please check again!"
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex items-center justify-center min-h-screen bg-gradient-to-tr from-blue-500 to-rose-500 p-6">
      <Card className="w-full max-w-md rounded-xl shadow-rose-500/20 shadow-xl">
        <CardHeader>
          <CardTitle className="flex items-center justify-center text-3xl font-bold text-blue-600">
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
