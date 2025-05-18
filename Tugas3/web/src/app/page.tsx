"use client";

import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import Image from "next/image";

export default function Home() {
  const router = useRouter();

  return (
    <div className="flex items-center justify-center min-h-screen bg-gradient-to-tr from-blue-300 to-white-500 p-6">
      <Card className="w-full max-w-xl shadow-2xl">
        <CardHeader>
          <CardTitle className="text-3xl text-center font-bold text-blue-600">
            Welcome to AxoSharkPing!
          </CardTitle>
          <Image
            src="/team.png"
            alt="Logo"
            width={100}
            height={100}
            className="mx-auto my-4 rounded-4xl shadow-lg"
          />
        </CardHeader>
        <CardContent className="flex flex-col gap-6 items-center">
          <p className="text-center text-gray-600 max-w-md">
            A secure and fun messaging experience, protected by cryptography and inspired by the power of Axolotls, Sharks, and Penguins.
          </p>
          <div className="flex gap-4">
            <Button variant="default" onClick={() => router.push("/login")}>Login</Button>
            <Button variant="outline" onClick={() => router.push("/register")}>Register</Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}