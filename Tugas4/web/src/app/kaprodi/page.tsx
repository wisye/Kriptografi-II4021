"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Card, CardContent } from "@/components/ui/card";
import { motion } from "framer-motion";

export default function Kaprodi() {
    const router = useRouter();
    const [transkripList, setTranskripList] = useState([]);

    useEffect(() => {
        fetch("http://localhost:8000/academic/list", {
            credentials: "include",
        })
            .then((res) => res.json())
            .then((data) => {
                if (data.academics) setTranskripList(data.academics);
            });
    }, []);

    const handleView = async (academicId: number) => {
        try {
            const res = await fetch(
                `http://localhost:8000/academic/${academicId}`,
                {
                    credentials: "include",
                }
            );
            if (!res.ok) throw new Error("Gagal fetch detail transkrip");

            const data = await res.json();
            localStorage.setItem("transkrip", JSON.stringify(data));
            localStorage.setItem("aes_key_hex", data?.aes_key_hex || "");
            router.push("/transcript");
        } catch (err) {
            alert("Gagal membuka transkrip");
        }
    };

    return (
        <div className="min-h-screen px-4 py-10 bg-gradient-to-br from-gray-950 to-gray-900 text-white">
            <motion.h1
                initial={{ opacity: 0, y: -20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.6 }}
                className="text-4xl font-bold text-center mb-8"
            >
                Daftar Transkrip Mahasiswa Prodi Anda
            </motion.h1>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6 max-w-6xl mx-auto">
                {transkripList.map((item: any) => (
                    <Card
                        key={item.id}
                        className="bg-white/10 text-white backdrop-blur-sm border border-white/20 ring-1 ring-white/10 cursor-pointer hover:ring-white/30 transition-all"
                        onClick={() => handleView(item.id)}
                    >
                        <CardContent className="p-4 space-y-1">
                            <p className="font-bold text-lg">{item.name}</p>
                            <p className="text-white/70 text-sm">
                                NIM: {item.nim}
                            </p>
                        </CardContent>
                    </Card>
                ))}
            </div>
        </div>
    );
}
