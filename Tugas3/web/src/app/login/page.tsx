"use client";

// import { useState } from "react";
// import { useRouter } from "next/navigation";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export default function Home() {
  return (
    <div className="flex items-center justify-center min-h-screen bg-gradient-to-tr from-blue-300 to-white-500 p-6">
      <Card className="w-full max-w-md">
        <CardHeader><CardTitle className="flex items-center justify-center text-3xl">Login</CardTitle></CardHeader>
        <CardContent className="flex flex-col gap-4">
          <Input placeholder="Username"/>
          <Input type="password" placeholder="Password" />
          <Button>Login</Button>
        </CardContent>
      </Card>
    </div>
  );
}
