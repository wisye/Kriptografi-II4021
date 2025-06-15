"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { motion } from "framer-motion";

export default function DecryptPDFPage() {
    const [rc4Key, setRc4Key] = useState("");
    const [file, setFile] = useState<File | null>(null);
    const [error, setError] = useState("");
    const [showKey, setShowKey] = useState(false);
    const router = useRouter();
    const handleDecryptDownload = async () => {
        if (!file || !rc4Key) {
            setError("Pastikan file dan kunci telah diisi.");
            return;
        }

        const formData = new FormData();
        formData.append("file", file);
        formData.append("rc4_key", rc4Key);

        try {
            const response = await fetch("http://localhost:8000/decrypt-rc4", {
                method: "POST",
                body: formData,
                credentials: "include",
            });

            if (!response.ok) throw new Error("Gagal mendekripsi file");

            const blob = await response.blob();
            const downloadUrl = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = downloadUrl;
            a.download = file.name.replace(".enc", "");
            a.click();
            a.remove();
        } catch (err) {
            setError("Kunci salah atau file gagal didekripsi.");
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
                    Dekripsi File Transkrip (PDF)
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
                        <CardContent className="space-y-4">
                            <Input
                                type="file"
                                accept=".enc"
                                onChange={(e) =>
                                    setFile(e.target.files?.[0] || null)
                                }
                                className="bg-white/10 font-normal text-white"
                            />
                            <div className="flex flex-col gap-1 relative">
                                <Input
                                    type={showKey ? "text" : "password"}
                                    placeholder="Masukkan Key..."
                                    value={rc4Key}
                                    onChange={(e) => setRc4Key(e.target.value)}
                                    className="bg-white/10 text-white font-normal placeholder:text-white/60"
                                />
                                <button
                                    type="button"
                                    onClick={() => setShowKey(!showKey)}
                                    className="absolute right-3 top-2 text-white font-normal text-sm hover:underline"
                                >
                                    {showKey ? "Hide" : "Show"}
                                </button>
                            </div>
                            <Button
                                onClick={handleDecryptDownload}
                                className="w-full text-white font-semibold bg-[#DF2389] hover:bg-[#c31c75] transition"
                            >
                                Decrypt Transcript and Download
                            </Button>
                            <Button
                                className="text-black items-center justify-center font-semibold w-full bg-[#23DF79] hover:bg-[#1ebf68] transition"
                                onClick={() => router.push("/kaprodi")}
                            >
                                Kembali ke Halaman Kaprodi
                            </Button>
                            {error && (
                                <p className="text-red-400 text-sm text-center">
                                    {error}
                                </p>
                            )}
                        </CardContent>
                    </Card>
                </motion.h1>
            </div>
        </div>
    );
}
