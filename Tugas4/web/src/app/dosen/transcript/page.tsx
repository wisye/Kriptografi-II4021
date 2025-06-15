"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { motion } from "framer-motion";
import { Checkbox } from "@/components/ui/checkbox";

export default function TranscriptPage() {
    const router = useRouter();
    const [transkrip, setTranskrip] = useState<any>(null);
    const [encryptPdf, setEncryptPdf] = useState(false);
    const [encryptionKey, setEncryptionKey] = useState("");
    const [aesKey, setAesKey] = useState("");
    const [verifikasiStatus, setVerifikasiStatus] = useState<
        "loading" | "verified" | "not-verified" | null
    >("loading");

    useEffect(() => {
        const stored = localStorage.getItem("transkrip");
        if (stored) {
            const parsed = JSON.parse(stored);
            setTranskrip(parsed);
        }

        const storedKey = localStorage.getItem("aes_key_hex");
        if (storedKey) {
            setAesKey(storedKey);
        }

        console.log("Transcript data and AES key loaded");
    }, []);

    useEffect(() => {
        const verifySignature = async () => {
            try {
                const stored = localStorage.getItem("transkrip");
                if (!stored) return;

                const parsed = JSON.parse(stored);
                const hashed = BigInt(`0x${parsed.hashed_data}`);
                const signature = BigInt(`0x${parsed.signature}`);
                const e = BigInt(parsed.kaprodi_public_key.e);
                const n = BigInt(parsed.kaprodi_public_key.n);
                const decrypted = signature ** e % n;
                console.log("=========================");
                console.log("Hashed Data:", hashed);
                console.log("Decrypted Signature:", decrypted);
                console.log("Signature:", signature);
                console.log("Public Key (e, n):", e, n);

                if (decrypted === hashed) {
                    setVerifikasiStatus("verified");
                } else {
                    setVerifikasiStatus("not-verified");
                }
            } catch (e) {
                console.error("Verification failed:", e);
                setVerifikasiStatus("not-verified");
            }
        };

        setTimeout(verifySignature, 100);
    }, []);

    const handleDownload = async () => {
        if (!transkrip || !transkrip.id) return;

        let baseUrl =
            process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

        if (encryptPdf && encryptionKey) {
            baseUrl += `/academic/${
                transkrip.id
            }/encrypted-pdf?rc4_key=${encodeURIComponent(encryptionKey)}`;
        } else {
            baseUrl += `/academic/${transkrip.id}/pdf`;
        }

        if (aesKey) {
            baseUrl +=
                (baseUrl.includes("?") ? "&" : "?") +
                `aes_key_hex=${encodeURIComponent(aesKey)}`;
        }

        const response = await fetch(baseUrl, {
            method: "GET",
            credentials: "include",
        });

        const blob = await response.blob();
        const downloadUrl = window.URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = downloadUrl;
        a.download = encryptPdf ? "transcript.pdf.enc" : "transcript.pdf";
        a.click();
        a.remove();
    };

    if (!transkrip)
        return (
            <p className="text-white text-center mt-20">
                Loading transcript...
            </p>
        );

    return (
        <div className="min-h-screen px-4 py-10 bg-gradient-to-br from-gray-950 to-gray-900 text-white">
            <div className="max-w-4xl mx-auto space-y-4">
                <motion.div
                    initial={{ opacity: 0, scale: 0.95 }}
                    animate={{ opacity: 1, scale: 1 }}
                    transition={{ duration: 0.6, delay: 0.3 }}
                    className="w-full"
                >
                    <Card className="bg-white/10 backdrop-blur-sm border border-white/20 ring-1 ring-white/10">
                        <CardContent className="p-6 space-y-6">
                            <h2 className="text-2xl text-white font-semibold text-center">
                                Laporan Transkrip {transkrip.name} :{" "}
                                {transkrip.nim}
                            </h2>

                            <table className="min-w-full text-sm text-white border border-white">
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

                            <div>
                                <p className="text-white font-semibold">
                                    Status Digital Signature:{" "}
                                    {verifikasiStatus === "loading" ? (
                                        <span className="text-yellow-400 animate-pulse">
                                            Verifying...
                                        </span>
                                    ) : verifikasiStatus === "verified" ? (
                                        <span className="text-green-400">
                                            ✅ Verified
                                        </span>
                                    ) : (
                                        <span className="text-red-400">
                                            ❌ Not Verified
                                        </span>
                                    )}
                                </p>
                            </div>

                            <div className="space-y-2">
                                <label className="flex items-center space-x-2">
                                    <Checkbox
                                        checked={encryptPdf}
                                        onCheckedChange={() =>
                                            setEncryptPdf(!encryptPdf)
                                        }
                                    />
                                    <span className="text-white">
                                        Enkripsi PDF saat diunduh
                                    </span>
                                </label>
                                {encryptPdf && (
                                    <Input
                                        placeholder="Masukkan kunci enkripsi PDF"
                                        className="bg-white/10 text-white placeholder:text-white/60"
                                        value={encryptionKey}
                                        onChange={(e) =>
                                            setEncryptionKey(e.target.value)
                                        }
                                    />
                                )}
                            </div>

                            <div className="text flex-col items-center justify-center flex center mt-6">
                                <Button
                                    className="text-white font-semibold bg-[#DF2389] w-96 hover:bg-[#c31c75] transition"
                                    onClick={handleDownload}
                                >
                                    Download Transcript
                                </Button>
                                <Button
                                    className="text-black items-center justify-center font-semibold w-96 mt-4 bg-[#23DF79] hover:bg-[#1ebf68] transition"
                                    onClick={() => router.push("/dosen")}
                                >
                                    Kembali ke Halaman Dosen
                                </Button>
                            </div>
                        </CardContent>
                    </Card>
                </motion.div>
            </div>
        </div>
    );
}
