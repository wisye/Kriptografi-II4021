// File: app/dosen/requestshamir/page.tsx
"use client";

import { useSearchParams, useRouter } from "next/navigation";
import { useState } from "react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { motion } from "framer-motion";

export default function RequestShamir() {
    const searchParams = useSearchParams();
    const router = useRouter();
    const academicId = searchParams.get("academic_id") || "";
    const name = searchParams.get("name") || "Mahasiswa";
    const nim = searchParams.get("nim") || "NIM";

    const [shares, setShares] = useState([
        { x: "", y: "" },
        { x: "", y: "" },
        { x: "", y: "" },
    ]);

    const handleInputChange = (
        index: number,
        field: "x" | "y",
        value: string
    ) => {
        const updatedShares = [...shares];
        updatedShares[index][field] = value;
        setShares(updatedShares);
    };

    const handleSubmit = async () => {
        try {
            const payload = {
                shares: shares.map((s) => ({
                    x: parseInt(s.x),
                    y: s.y,
                })),
            };

            const res = await fetch(
                `http://localhost:8000/academic/${academicId}/view-sss`,
                {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                    },
                    credentials: "include",
                    body: JSON.stringify(payload),
                }
            );

            if (!res.ok) {
                const errData = await res.json();
                throw new Error(
                    errData.detail || "Gagal rekonstruksi AES key."
                );
            }

            const blob = await res.blob();
            const downloadUrl = window.URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = downloadUrl;
            a.download = `transcript_${academicId}.pdf`;
            document.body.appendChild(a);
            a.click();
            a.remove();
            console.log("Transkrip berhasil diunduh");
            console.log("Payload:", payload);
            console.log("Response:", res);
        } catch (err: any) {
            alert(err.message);
        }
    };

    return (
        <motion.div
            className="min-h-screen px-4 py-10 bg-gradient-to-br from-gray-950 to-gray-900 text-white"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.8 }}
        >
            <motion.h1
                initial={{ opacity: 0, y: -30 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.8, delay: 0.1 }}
                className="text-3xl font-bold text-center mb-2"
            >
                Request Access for {name} ({nim})
            </motion.h1>

            <motion.p
                initial={{ opacity: 0, y: -10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.6, delay: 0.2 }}
                className="text-center text-white/70 mb-6"
            >
                Masukkan 3 Part of Keys (SSS) untuk membuka akses. Kode akses
                didapatkan dari dosen lain!
            </motion.p>

            <motion.div
                className="flex flex-col items-center space-y-4 justify-center mb-8"
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.6, delay: 0.3 }}
            >
                <Button
                    className="text-black items-center justify-center font-semibold w-96 mt-4 bg-[#23DF79] hover:bg-[#1ebf68] transition"
                    onClick={() => router.push("/dosen")}
                >
                    Kembali ke Halaman Dosen
                </Button>
            </motion.div>

            <motion.div
                className="max-w-2xl mx-auto space-y-6"
                initial="hidden"
                animate="visible"
                variants={{
                    visible: {
                        transition: { staggerChildren: 0.2 },
                    },
                }}
            >
                {shares.map((share, index) => (
                    <motion.div
                        key={index}
                        className="transition-transform duration-300"
                        initial={{ opacity: 0, y: 40, scale: 0.95 }}
                        animate={{ opacity: 1, y: 0, scale: 1 }}
                        transition={{
                            duration: 0.5,
                            ease: "easeOut",
                            delay: index * 0.2,
                        }}
                    >
                        <Card className="bg-white/5 text-white border border-white/10">
                            <CardContent className="space-y-3 p-4">
                                <p className="text-lg font-semibold">
                                    Part {index + 1}
                                </p>
                                <Input
                                    placeholder="x (angka)"
                                    value={share.x}
                                    onChange={(e) =>
                                        handleInputChange(
                                            index,
                                            "x",
                                            e.target.value
                                        )
                                    }
                                    className="text-white"
                                />
                                <Input
                                    placeholder="y (hex string)"
                                    value={share.y}
                                    onChange={(e) =>
                                        handleInputChange(
                                            index,
                                            "y",
                                            e.target.value
                                        )
                                    }
                                    className="text-white"
                                />
                            </CardContent>
                        </Card>
                    </motion.div>
                ))}

                <motion.div
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.6, delay: 0.5 }}
                    className="text-yellow-400 text-sm italic text-center"
                >
                    * Salah satu part harus berasal dari dosen pembimbing
                    transkrip asli
                </motion.div>

                <motion.div
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.6, delay: 0.6 }}
                    className="flex justify-center"
                >
                    <Button
                        onClick={handleSubmit}
                        className="bg-green-500 hover:bg-green-600 text-black font-semibold px-6 py-2"
                    >
                        Kirim Request dan Unduh Transkrip
                    </Button>
                </motion.div>
            </motion.div>
        </motion.div>
    );
}
