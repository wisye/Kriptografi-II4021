"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Card, CardContent } from "@/components/ui/card";
import { motion } from "framer-motion";
import { Button } from "@/components/ui/button";

export default function Dosen() {
    const router = useRouter();
    const [transkripList, setTranskripList] = useState([]);
    const [mabaList, setMabaList] = useState([]); // ✅ STATE UNTUK MABA
    const [username, setUsername] = useState("");

    useEffect(() => {
        const storedUser = localStorage.getItem("user");
        if (storedUser) {
            const parsed = JSON.parse(storedUser);
            setUsername(parsed.username);
        }

        // Fetch Transkrip
        fetch("http://localhost:8000/academic/list", {
            credentials: "include",
        })
            .then((res) => res.json())
            .then((data) => {
                if (data.academics) setTranskripList(data.academics);
            });

        // ✅ Fetch Mahasiswa Baru
        fetch("http://localhost:8000/user/list_maba", {
            credentials: "include",
        })
            .then((res) => res.json())
            .then((data) => {
                if (data.maba_list) setMabaList(data.maba_list);
            });
    }, []);

    const handleView = async (academicId: number) => {
        try {
            const res = await fetch(
                `http://localhost:8000/academic/${academicId}`,
                { credentials: "include" }
            );
            if (!res.ok) throw new Error("Gagal fetch detail transkrip");

            const data = await res.json();
            localStorage.setItem("transkrip", JSON.stringify(data));
            localStorage.setItem("aes_key_hex", data?.aes_key_hex || "");
            router.push("/dosen/transcript");
        } catch (err) {
            alert("Gagal membuka transkrip");
        }
    };

    const getJudul = () => {
        if (username === "wali_if")
            return "Transkrip Mahasiswa Bimbingan Prodi IF";
        if (username === "wali_sti")
            return "Transkrip Mahasiswa Bimbingan Prodi STI";
        return "Transkrip Mahasiswa Bimbingan Anda";
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
            </motion.h1>

            <div className="flex justify-center mb-8">
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

            <div className="flex flex-col gap-4 max-w-3xl mx-auto">
                {/* ✅ Tampilkan Transkrip */}
                {transkripList.map((item: any) => (
                    <Card
                        key={item.id}
                        className="bg-white/10 text-white backdrop-blur-sm border border-white/20 ring-1 ring-white/10 cursor-pointer hover:ring-white/30 transition-all"
                        onClick={() => handleView(item.id)}
                    >
                        <CardContent className="flex flex-col justify-center items-center space-y-1">
                            <p className="font-bold text-3xl">{item.name}</p>
                            <p className="text-white/90 text-xl">
                                NIM: {item.nim}
                            </p>
                        </CardContent>
                    </Card>
                ))}

                {/* ✅ Tampilkan MABA */}
                {mabaList.length > 0 && (
                    <div className="mt-10">
                        <h2 className="text-2xl font-semibold text-white text-center mb-4">
                            Mahasiswa Baru Tanpa Transkrip
                        </h2>
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
                            className="flex flex-col gap-4"
                        >
                            {mabaList.map((maba: any, index: number) => (
                                <motion.div
                                    key={index}
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
                                            <p className="font-bold text-xl">
                                                {maba.username}
                                            </p>
                                            <p className="text-white/70">
                                                Prodi: {maba.major}
                                            </p>
                                        </CardContent>
                                    </Card>
                                </motion.div>
                            ))}
                        </motion.div>
                    </div>
                )}
            </div>
        </div>
    );
}
