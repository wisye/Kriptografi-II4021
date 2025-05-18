"use client";

// import { useState } from "react";
// import { useRouter } from "next/navigation";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import Link
 from "next/link";
export default function Home() {
  return (
    <div className="flex items-center justify-center min-h-screen bg-gradient-to-tr from-blue-500 to-rose-500 p-6">
      <Card className="w-full rounded-xl max-w-md shadow-rose-500/20 shadow-xl">
        <CardHeader><CardTitle className="flex items-center justify-center font-bold text-blue-600 text-3xl">Login</CardTitle></CardHeader>
        <CardContent className="flex flex-col gap-4">
          <Input placeholder="Username"/>
          <Input type="password" placeholder="Password" />
          <Button>Login</Button>
          <h3>
            Don't have an account? <Link href="/register" className="text-blue-600 hover:underline">Login</Link>
          </h3>
        </CardContent>
      </Card>
    </div>
  );
}
