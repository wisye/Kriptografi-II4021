"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import api from "@/lib/api";
import { sha3_256 } from "js-sha3";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import Link from "next/link";

export default function LoginPage() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [privateKey, setPrivateKey] = useState<string | null>(null);
  const router = useRouter();
  const redirectTarget = "/chatroom";

  const handleLogin = async () => {
    setError(null);
    setSuccess(null);

    if (!username.trim() || !password.trim()) {
      setError("Username or password can't be empty!");
      return;
    }

    setLoading(true);
    try {
      const pwdHash = sha3_256(password);
      const form = new URLSearchParams();
      form.append("username", username);
      form.append("password", pwdHash);

      await api.post("/api/login", form, {
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
      });

      
      if (!localStorage.getItem("privateKey")) {
        alert(
          "Register first to get private key"
        );
      }
      
      setSuccess("Login berhasil! Mengalihkan...");
      setTimeout(() => router.push(redirectTarget), 300);
    } catch (err: any) {
      const status = err.response?.status;
      const detail = err.response?.data?.detail ?? "";

      if (status === 409 || /already logged in/i.test(detail)) {
        router.push(redirectTarget);
        return;
      }

      setError(detail || "Terjadi kesalahan.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex items-center justify-center min-h-screen bg-gradient-to-tr from-blue-500 to-rose-500 p-6">
      <Card className="w-full max-w-md rounded-xl shadow-rose-500/20 shadow-xl">
        <CardHeader>
          <CardTitle className="flex items-center justify-center text-3xl font-bold text-blue-600">
            Login
          </CardTitle>
        </CardHeader>
        <CardContent>
          <form
            onSubmit={(e) => {
              e.preventDefault(); // prevent page refresh
              handleLogin();      // call your login function
            }}
            className="flex flex-col gap-4"
          >
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
            <Button type="submit" disabled={loading}>
              {loading ? "Processing…" : "Login"}
            </Button>
            {error && <p className="text-red-600 text-sm">{error}</p>}
            {success && <p className="text-green-600 text-sm">{success}</p>}
            <h3>
              Don&apos;t have an account?{" "}
              <Link href="/register" className="text-blue-600 hover:underline">
                Register
              </Link>
            </h3>
          </form>
        </CardContent>

      </Card>
    </div>
  );
}
