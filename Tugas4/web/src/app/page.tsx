"use client";

import { useState } from "react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { motion } from "framer-motion";
import Image from "next/image";

export default function Home() {
    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");
    const [error, setError] = useState("");
    const handleLogin = async () => {
        try {
            const response = await fetch("http://localhost:8000/login", {
                method: "POST",
                credentials: "include",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({ username, password }),
            });

            if (!response.ok) {
                throw new Error("Login gagal");
            }

            const data = await response.json();
            console.log("Login berhasil:", data);

            localStorage.setItem("user", JSON.stringify(data.user));

            if (data.user.role === "Mahasiswa") {
                window.location.href = "/mahasiswa";
            } else if (data.user.role === "Dosen Wali") {
                window.location.href = "/dosen";
            } else if (data.user.role === "Ketua Program Studi") {
                window.location.href = "/kaprodi";
            }
        } catch (err) {
            setError(
                "Kayaknya username atau password kamu salah! :) Tanyakan kepada Führer-mu!"
            );
        }
    };

    return (
        <div className="min-h-screen flex flex-col items-center justify-center bg-gradient-to-br from-gray-950 to-gray-900 p-4">
            <motion.h1
                initial={{ opacity: 0, y: -30 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.8 }}
                className="text-6xl font-bold text-white mb-8 text-center"
            >
                SIXty<span className="text-[#DF2389]">Nein!</span>
            </motion.h1>
            <motion.h2
                initial={{ opacity: 0, y: -10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.8, delay: 0.2 }}
                className="text-2xl text-white mb-8 text-center"
            >
                Welcome to Institut Teknologi Berlin!
            </motion.h2>
            <motion.div
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ duration: 0.6, delay: 0.3 }}
                className="w-full max-w-sm"
            >
                <Card className="rounded-2xl shadow-xl bg-white/10 border border-white/20 ring-1 ring-white/10">
                    <div className="flex items-center justify-center">
                        <h1 className="text-2xl text-white justify-center items-center">
                            Log in dulu PIPS!
                        </h1>
                    </div>
                    <CardContent className="space-y-4">
                        <Input
                            placeholder="Username"
                            className="bg-white/10 text-white placeholder:text-white/60"
                            value={username}
                            onChange={(e) => setUsername(e.target.value)}
                        />
                        <Input
                            type="password"
                            placeholder="Password"
                            className="bg-white/10 text-white placeholder:text-white/60"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                        />
                        <Button
                            onClick={handleLogin}
                            className="w-full text-white font-semibold bg-[#23DF79] hover:bg-[#1ebf68] transition"
                        >
                            Login
                        </Button>
                        {error && (
                            <p className="text-sm text-red-400 font-medium text-center">
                                {error}
                            </p>
                        )}
                    </CardContent>
                </Card>
            </motion.div>

            <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 1, duration: 0.6 }}
                className="mt-16 text-center"
            >
                <Image
                    src="/team.webp" // ganti dengan path foto kamu
                    alt="Foto Pembuat"
                    width={90}
                    height={90}
                    className="rounded-full mx-auto mb-2"
                />
                <p className="text-xl mt-8 text-white">
                    Lydia Gracia / 18222035 👨‍💻
                </p>
                <p className="text-xl text-white">
                    Irfan Musthofa / 18222056 👨‍💻
                </p>
                <p className="text-xl text-white">
                    Wisyendra Lunarmalam / 18222095 👨‍💻
                </p>
            </motion.div>
        </div>
    );
}
