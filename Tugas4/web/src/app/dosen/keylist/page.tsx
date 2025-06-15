"use client";

import { useEffect, useState } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { motion } from "framer-motion";
import { Button } from "@/components/ui/button";
import { useRouter } from "next/navigation";

export default function KeyList() {
    const [keyList, setKeyList] = useState([]);
    const router = useRouter();

    useEffect(() => {
        fetch("http://localhost:8000/shamir/my_splits", {
            credentials: "include",
        })
            .then((res) => res.json())
            .then((data) => {
                if (data.splits) setKeyList(data.splits);
            });
    }, []);

    return (
        <div className="min-h-screen px-4 py-10 bg-gradient-to-br from-gray-950 to-gray-900 text-white">
            <motion.h1
                initial={{ opacity: 0, y: -20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.6 }}
                className="text-4xl font-bold text-center mb-8"
            >
                Daftar Keys
            </motion.h1>
            <div className="flex flex-col items-center space-y-4 justify-center mb-8">
                <Button
                    className="text-black items-center justify-center font-semibold w-96 mt-4 bg-[#23DF79] hover:bg-[#1ebf68] transition"
                    onClick={() => router.push("/dosen")}
                >
                    Kembali ke Halaman Dosen
                </Button>
            </div>

            <div className="flex flex-col gap-4 max-w-4xl mx-auto">
                <motion.div
                    initial="hidden"
                    animate="visible"
                    variants={{
                        hidden: {},
                        visible: { transition: { staggerChildren: 0.15 } },
                    }}
                >
                    {keyList.map((key: any, idx) => (
                        <motion.div
                            key={idx}
                            variants={{
                                hidden: { opacity: 0, y: 20 },
                                visible: { opacity: 1, y: 0 },
                            }}
                            transition={{ duration: 0.5, ease: "easeOut" }}
                        >
                            <Card className="bg-white/5 text-white backdrop-blur-sm m-8 border border-white/10 ring-1 ring-white/5">
                                <CardContent className="p-4 space-y-2 m-8">
                                    <p>
                                        <strong>Nama Mahasiswa:</strong>{" "}
                                        {key.student_name}
                                    </p>
                                    <p>
                                        <strong>NIM:</strong> {key.student_nim}
                                    </p>
                                    <p>
                                        <strong>Share X:</strong> {key.share_x}
                                    </p>
                                    <p>
                                        <strong>Share Y:</strong> {key.share_y}
                                    </p>
                                    <p>
                                        <strong>Prime:</strong> {key.prime}
                                    </p>
                                    <p>
                                        <strong>Threshold:</strong>{" "}
                                        {key.threshold}
                                    </p>
                                    <p>
                                        <strong>Requested By:</strong>{" "}
                                        {key.requested_by}
                                    </p>
                                    <p>
                                        <strong>Dibuat Pada:</strong>{" "}
                                        {new Date(
                                            key.created_at
                                        ).toLocaleString()}
                                    </p>
                                </CardContent>
                            </Card>
                        </motion.div>
                    ))}
                </motion.div>
            </div>
        </div>
    );
}
