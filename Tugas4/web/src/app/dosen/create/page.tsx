"use client";

import { useSearchParams, useRouter } from "next/navigation";
import { useState, useMemo } from "react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { motion } from "framer-motion";

export default function Create() {
    const searchParams = useSearchParams();
    const router = useRouter();
    const nimParam = searchParams.get("nim") || "";
    const [showAesKey, setShowAesKey] = useState(false);
    const [nim, setNim] = useState(nimParam);
    const [name, setName] = useState("");
    const [aesKey, setAesKey] = useState("");
    const [grades, setGrades] = useState(Array(10).fill("0.0"));

    const courseList = [
        { code: "IF1001", name: "Computer Architecture", credits: 2 },
        { code: "IF1002", name: "Distributed System", credits: 2 },
        { code: "IF1003", name: "Computer Networks", credits: 3 },
        { code: "IF1004", name: "Operating Systems", credits: 3 },
        { code: "IF1005", name: "Integrated System Technology", credits: 2 },
        { code: "II1001", name: "Computer Organization", credits: 2 },
        { code: "II1002", name: "Enterprise Architecture", credits: 2 },
        { code: "II1003", name: "Software Engineering", credits: 3 },
        { code: "II1004", name: "IST Management", credits: 3 },
        { code: "II1005", name: "UI/UX Design", credits: 2 },
    ];

    const handleGradeChange = (index: number, value: string) => {
        const updated = [...grades];
        updated[index] = value;
        setGrades(updated);
    };

    const ipk = useMemo(() => {
        let totalWeight = 0;
        let totalCredits = 0;
        grades.forEach((grade, i) => {
            const g = parseFloat(grade);
            const credits = courseList[i].credits;
            if (!isNaN(g)) {
                totalWeight += g * credits;
                totalCredits += credits;
            }
        });
        return totalCredits > 0
            ? (totalWeight / totalCredits).toFixed(2)
            : "0.00";
    }, [grades]);

    const handleSubmit = async () => {
        if (!nim || !name || !aesKey || grades.includes("")) {
            alert("Lengkapi semua data!");
            return;
        }

        const coursePayload = courseList.map((c, i) => ({
            course_code: c.code,
            course_name: c.name,
            credits: c.credits,
            grade: parseFloat(grades[i]),
        }));

        const payload = {
            nim,
            name,
            aes_key_hex: hashedKey,
            courses: coursePayload,
        };

        try {
            const res = await fetch("http://localhost:8000/academic/input", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                credentials: "include",
                body: JSON.stringify(payload),
            });

            const result = await res.json();

            if (res.ok) {
                const academicId = result.academic_id;

                // 🔑 Call Shamir Split
                try {
                    const shamirRes = await fetch(
                        `http://localhost:8000/shamir/request_split/${academicId}`,
                        {
                            method: "POST",
                            credentials: "include",
                        }
                    );

                    const shamirResult = await shamirRes.json();

                    if (shamirRes.ok) {
                        const shareX = shamirResult.my_share?.share_x;
                        const shareY = shamirResult.my_share?.share_y_hex;
                        const receivers =
                            shamirResult.receiving_dosen_wali_usernames;
                        const pembimbing =
                            shamirResult.mahasiswa_dosen_wali_username;

                        const message = `
✅ Transkrip & Shamir's Split berhasil disimpan!

🔐 Potongan Kunci Anda (My Share):
  • x = ${shareX}
  • y = ${shareY}

👥 Dosen Wali Penerima Kunci:
  • ${receivers.join("\n  • ")}

👨‍🏫 Dosen Pembimbing Mahasiswa: ${pembimbing}
                    `;

                        alert(message);
                        router.push("/dosen");
                    } else {
                        alert(
                            "Gagal melakukan Shamir Split:\n" +
                                shamirResult.detail
                        );
                    }
                } catch (e) {
                    alert("Gagal memanggil API Shamir Split.");
                }
            } else {
                alert("Gagal menyimpan transkrip:\n" + result.detail);
            }
        } catch (error) {
            alert("Gagal mengirim data.");
        }
    };

    return (
        <div className="min-h-screen px-4 py-10 bg-gradient-to-br from-gray-950 to-gray-900 text-white">
            <h1 className="text-3xl font-bold text-center mb-6">
                Form Tambah Transkrip
            </h1>

            <div className="max-w-5xl mx-auto space-y-6">
                <Card className="bg-white/10 border border-white/20">
                    <CardContent className="space-y-6 p-6">
                        <Input
                            value={nim}
                            readOnly
                            className="bg-white/5 text-white"
                        />
                        <Input
                            value={name}
                            onChange={(e) => setName(e.target.value)}
                            maxLength={24}
                            placeholder="Nama Mahasiswa"
                            className="bg-white/5 text-white"
                        />
                        <div className="flex flex-col gap-2">
                            <label className="text-sm text-white font-semibold">
                                AES Key
                            </label>
                            <div className="relative">
                                <Input
                                    type={showAesKey ? "text" : "password"}
                                    value={aesKey}
                                    onChange={(e) => setAesKey(e.target.value)}
                                    className="bg-white/5 text-white"
                                />
                                <button
                                    type="button"
                                    onClick={() => setShowAesKey(!showAesKey)}
                                    className="absolute right-3 top-2 text-white text-sm hover:underline"
                                >
                                    {showAesKey ? "Hide" : "Show"}
                                </button>
                            </div>
                        </div>

                        <div>
                            <h2 className="font-semibold text-white text-lg mb-4">
                                Nilai Mata Kuliah
                            </h2>
                            <motion.table
                                initial="hidden"
                                animate="visible"
                                variants={{
                                    visible: {
                                        transition: { staggerChildren: 0.05 },
                                    },
                                }}
                                className="w-full text-white border-collapse rounded-xl overflow-hidden"
                            >
                                <thead>
                                    <tr className="bg-white/10">
                                        <th className="p-3 border border-white/20">
                                            Kode
                                        </th>
                                        <th className="p-3 border border-white/20">
                                            Mata Kuliah
                                        </th>
                                        <th className="p-3 border border-white/20">
                                            SKS
                                        </th>
                                        <th className="p-3 border border-white/20">
                                            Nilai
                                        </th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {courseList.map((course, index) => (
                                        <motion.tr
                                            key={index}
                                            initial={{ opacity: 0, y: 10 }}
                                            animate={{ opacity: 1, y: 0 }}
                                            transition={{ delay: index * 0.05 }}
                                            className="bg-white/5 hover:bg-white/10 transition-all"
                                        >
                                            <td className="p-3 border border-white/20 text-center">
                                                {course.code}
                                            </td>
                                            <td className="p-3 border border-white/20">
                                                {course.name}
                                            </td>
                                            <td className="p-3 border border-white/20 text-center">
                                                {course.credits}
                                            </td>
                                            <td className="p-3 border border-white/20 text-center">
                                                <input
                                                    type="range"
                                                    min="0"
                                                    max="4"
                                                    step="0.1"
                                                    value={grades[index]}
                                                    onChange={(e) =>
                                                        handleGradeChange(
                                                            index,
                                                            e.target.value
                                                        )
                                                    }
                                                    className="w-full accent-[#23DF79]"
                                                />
                                                <div className="text-sm text-center mt-1">
                                                    {parseFloat(
                                                        grades[index]
                                                    ).toFixed(1)}
                                                </div>
                                            </td>
                                        </motion.tr>
                                    ))}
                                </tbody>
                            </motion.table>
                        </div>
                        <div className="pt-4 text-center">
                            <p className="text-md font-semibold text-white mb-2">
                                Total SKS:{" "}
                                {courseList.reduce(
                                    (sum, c) => sum + c.credits,
                                    0
                                )}
                            </p>
                            <p className="text-2xl font-bold text-white">
                                IPK:{" "}
                                <span className="text-[#23DF79]">{ipk}</span>
                            </p>
                        </div>
                        <div className="flex justify-between pt-6">
                            <Button
                                variant="outline"
                                className="text-white font-semibold bg-[#DF2389] hover:bg-[#c31c75] transition"
                                onClick={() => router.push("/dosen")}
                            >
                                Kembali
                            </Button>
                            <Button
                                className="bg-[#23DF79] hover:bg-[#1fcf6a] text-black font-semibold"
                                onClick={handleSubmit}
                            >
                                Tambah Transkrip
                            </Button>
                        </div>
                    </CardContent>
                </Card>
            </div>
        </div>
    );
}
