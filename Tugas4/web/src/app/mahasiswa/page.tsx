"use client";

import { useState, useEffect } from "react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { motion } from "framer-motion";
import Link from "next/link";

export default function Mahasiswa() {
    const [decryptionKey, setDecryptionKey] = useState("");
    const [academicId, setAcademicId] = useState<number | null>(null);
    const [transkrip, setTranskrip] = useState(null);
    const [error, setError] = useState("");
    const [username, setUsername] = useState("Mahasiswa");
    const [aesKey, setAesKey] = useState("");

    useEffect(() => {
        const storedUser = localStorage.getItem("user");
        if (storedUser) {
            const user = JSON.parse(storedUser);
            setUsername(user.username);
        }

        fetch("http://localhost:8000/academic/list", {
            credentials: "include",
        })
            .then((res) => res.json())
            .then((data) => {
                if (data.academics && data.academics.length > 0) {
                    setAcademicId(data.academics[0].id);
                }
            })
            .catch((err) => console.error("Error fetching list:", err));
    }, []);

    const handleDecrypt = async () => {
        if (!academicId) return;
        try {
            const response = await fetch(
                `http://localhost:8000/academic/${academicId}?aes_key_hex=${decryptionKey}`,
                {
                    method: "GET",
                    credentials: "include",
                }
            );

            if (!response.ok) throw new Error("Gagal dekripsi");
            console.log("Response status:", response.status);
            console.log("Decryption key:", decryptionKey);
            setAesKey(decryptionKey);
            console.log("Fetching data for academic ID:", academicId);
            const data = await response.json();
            console.log("Decrypted data:", data);
            setTranskrip(data);
            setError("");
        } catch (err) {
            setError("Kunci salah atau data tidak dapat didekripsi.");
            setTranskrip(null);
        }
    };

    return (
        <div className="min-h-screen px-4 py-10 bg-gradient-to-br from-gray-950 to-gray-900 text-white">
            <div className="text-center mb-10">
                <motion.h1
                    initial={{ opacity: 0, y: -20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.6 }}
                    className="text-4xl font-bold"
                >
                    Hai, {username}!
                </motion.h1>
            </div>

            <div className="max-w-xl mx-auto space-y-4">
                <motion.h1
                    initial={{ opacity: 0, y: -20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.6 }}
                    className="text-4xl font-bold"
                >
                    <Card className="bg-white/10 backdrop-blur-sm border border-white/20 ring-1 ring-white/10">
                        <CardContent className="space-y-2">
                            <h1 className="text-2xl text-white font-semibold mb-4 text-center">
                                Dekripsi Transkrip Akademik
                            </h1>
                            <Input
                                placeholder="Masukkan kunci dekripsi AES..."
                                className="bg-white/10 text-white font-normal placeholder:text-white/60"
                                value={decryptionKey}
                                onChange={(e) =>
                                    setDecryptionKey(e.target.value)
                                }
                            />
                            <div className="flex items-center justify-between gap-4 mt-4">
                                <div className="flex-1">
                                    <Button
                                        onClick={handleDecrypt}
                                        className="w-full text-black font-semibold bg-[#23DF79] hover:bg-[#1ebf68]"
                                    >
                                        Dekripsi Transkrip (View)
                                    </Button>
                                </div>
                                <div className="flex-1">
                                    <Link href="/decryptpdf">
                                        <Button className="w-full text-black font-semibold bg-[#23DF79] hover:bg-[#1ebf68]">
                                            Dekripsi Transkrip (PDF)
                                        </Button>
                                    </Link>
                                </div>
                            </div>

                            <Button
                                className="text-white w-full font-semibold bg-[#DF2389] hover:bg-[#c31c75] transition"
                                onClick={() => {
                                    localStorage.clear();
                                    window.location.href = "/";
                                }}
                            >
                                Logout
                            </Button>

                            {error && (
                                <p className="text-red-400 text-sm text-center">
                                    {error}
                                </p>
                            )}
                        </CardContent>
                    </Card>
                </motion.h1>
                {transkrip && (
                    <motion.div
                        initial={{ opacity: 0, scale: 0.95 }}
                        animate={{ opacity: 1, scale: 1 }}
                        transition={{ duration: 0.6, delay: 0.3 }}
                        className="w-full"
                    >
                        <Card className="bg-white/10 backdrop-blur-sm border border-white/20 ring-1 ring-white/10">
                            <CardContent>
                                <div className="mt-4 overflow-x-auto">
                                    <h2 className="text-2xl pb-4 text-white font-semibold mb-4 text-center">
                                        Laporan Transkrip {transkrip.name} :{" "}
                                        {transkrip.nim}
                                    </h2>

                                    <table className="min-w-full text-sm text-white border border-white/20">
                                        <thead className="bg-white/10">
                                            <tr>
                                                <th className="px-4 py-2 border">
                                                    Kode MK
                                                </th>
                                                <th className="px-4 py-2 border">
                                                    Nama MK
                                                </th>
                                                <th className="px-4 py-2 border">
                                                    SKS
                                                </th>
                                                <th className="px-4 py-2 border">
                                                    Nilai
                                                </th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {transkrip.courses.map(
                                                (mk: any, i: number) => (
                                                    <tr
                                                        key={i}
                                                        className="even:bg-white/5"
                                                    >
                                                        <td className="px-4 py-2 border">
                                                            {mk.course_code}
                                                        </td>
                                                        <td className="px-4 py-2 border">
                                                            {mk.course_name}
                                                        </td>
                                                        <td className="px-4 py-2 border">
                                                            {mk.credits}
                                                        </td>
                                                        <td className="px-4 py-2 border">
                                                            {mk.grade}
                                                        </td>
                                                    </tr>
                                                )
                                            )}
                                            <tr className="bg-white/10">
                                                <td
                                                    colSpan={3}
                                                    className="px-4 py-2 border font-bold text-right"
                                                >
                                                    IPK
                                                </td>
                                                <td className="px-4 py-2 border font-bold">
                                                    {transkrip.ipk}
                                                </td>
                                            </tr>
                                        </tbody>
                                    </table>
                                    <div className="text-center mt-6">
                                        <Button
                                            className="text-white font-semibold bg-[#DF2389] hover:bg-[#c31c75] transition"
                                            onClick={() => {
                                                if (transkrip) {
                                                    localStorage.setItem(
                                                        "transkrip",
                                                        JSON.stringify(
                                                            transkrip
                                                        )
                                                    );
                                                    localStorage.setItem(
                                                        "aes_key_hex",
                                                        aesKey
                                                    );
                                                    window.location.href =
                                                        "/transcript";
                                                }
                                            }}
                                        >
                                            Download Transcript
                                        </Button>
                                    </div>
                                </div>
                            </CardContent>
                        </Card>
                    </motion.div>
                )}
            </div>
        </div>
    );
}
