"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Card, CardContent } from "@/components/ui/card";
import { motion } from "framer-motion";
import { Button } from "@/components/ui/button";
import Link from "next/link";
const baseUrl = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export default function Kaprodi() {
    const router = useRouter();
    const [transkripList, setTranskripList] = useState([]);
    const [username, setUsername] = useState("");

    useEffect(() => {
        const storedUser = localStorage.getItem("user");
        if (storedUser) {
            const parsed = JSON.parse(storedUser);
            setUsername(parsed.username);
        }

        fetch(`${baseUrl}/academic/list`, {
            credentials: "include",
        })
            .then((res) => res.json())
            .then((data) => {
                if (data.academics) setTranskripList(data.academics);
            });
    }, []);

    const handleView = async (academicId: number) => {
        try {
            const res = await fetch(`${baseUrl}/academic/${academicId}`, {
                credentials: "include",
            });
            if (!res.ok) throw new Error("Gagal fetch detail transkrip");

            const data = await res.json();
            localStorage.setItem("transkrip", JSON.stringify(data));
            localStorage.setItem("aes_key_hex", data?.aes_key_hex || "");
            router.push("/kaprodi/transcript");
        } catch (err) {
            alert("Gagal membuka transkrip");
        }
    };

    const getJudul = () => {
        if (username === "admin_if")
            return "Daftar Transkrip Mahasiswa Prodi IF";
        if (username === "admin_sti")
            return "Daftar Transkrip Mahasiswa Prodi STI";
        return "Daftar Transkrip Mahasiswa Prodi Anda";
    };

    return (
        <div className="min-h-screen px-4 py-10 bg-gradient-to-br from-gray-950 to-gray-900 text-white">
            <motion.h1
                initial={{ opacity: 0, y: -20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.6 }}
                className="text-4xl font-bold text-center mb-8"
            >
                {getJudul()}
                <div className="flex justify-center mb-4 mt-8">
                    <Button
                        className="text-white w-96 font-semibold bg-[#DF2389] hover:bg-[#c31c75] transition"
                        onClick={() => {
                            localStorage.clear();
                            window.location.href = "/";
                        }}
                    >
                        Logout
                    </Button>
                </div>
                <div className="flex justify-center mb-8">
                    <Link href="/kaprodi/decryptpdf">
                        <Button className="w-96 text-black font-semibold bg-[#23DF79] hover:bg-[#1ebf68]">
                            Dekripsi Transkrip (PDF)
                        </Button>
                    </Link>
                </div>
            </motion.h1>

            <motion.div
                initial="hidden"
                animate="visible"
                variants={{
                    visible: {
                        transition: {
                            staggerChildren: 0.15,
                        },
                    },
                }}
                className="flex flex-col gap-4 max-w-3xl mx-auto"
            >
                {transkripList.map((item: any) => (
                    <motion.div
                        key={item.id}
                        variants={{
                            hidden: { opacity: 0, y: 20 },
                            visible: { opacity: 1, y: 0 },
                        }}
                        transition={{
                            duration: 0.4,
                            ease: "easeOut",
                        }}
                    >
                        <Card className="bg-white/5 text-white backdrop-blur-sm border border-white/10 ring-1 ring-white/5">
                            <CardContent className="flex flex-col justify-center items-center space-y-1">
                                <p className="font-bold text-xl">{item.name}</p>
                                <p className="text-white/70">NIM: {item.nim}</p>
                                <Button
                                    onClick={() => handleView(item.id)}
                                    className="mt-2 text-black font-semibold bg-[#23A6DF] hover:bg-[#1e8fc2] transition"
                                >
                                    Lihat Transkrip
                                </Button>
                            </CardContent>
                        </Card>
                    </motion.div>
                ))}
            </motion.div>
        </div>
    );
}
