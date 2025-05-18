"use client";

import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import Link from "next/link";
export default function Home() {
  return (
    <div className="flex items-center justify-center min-h-screen bg-gradient-to-tr from-blue-500 to-rose-500 p-6">
      <Card className="w-full rounded-xl max-w-md shadow-rose-500/20 shadow-xl">
        <CardHeader><CardTitle className="flex items-center font-bold text-blue-600 justify-center text-3xl">Register</CardTitle></CardHeader>
        <CardContent className="flex flex-col gap-4">
          <Input placeholder="Username" />
          <Input type="password" placeholder="Password" />
          <Button>Register</Button>
          <h3>
            Already have an account? <Link href="/login" className="text-blue-600 hover:underline">Login</Link>
          </h3>
        </CardContent>
      </Card>
    </div>
  );
}
