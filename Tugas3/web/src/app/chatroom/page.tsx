"use client";

import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import api from "@/lib/api";
import {
  signMessage,
  verifySignature,
  hashMessage,
  normalizeContent,
} from "@/lib/ecdsa";

interface User {
  id: number;
  username: string;
  public_key_x: string;
  public_key_y: string;
}

interface Message {
  id?: number;
  sender: number;
  receiver: number;
  content: string;
  content_hash: string;
  signature_r: string;
  signature_s: string;
  verified?: boolean;
}

export default function Chatroom() {
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [users, setUsers] = useState<User[]>([]);
  const [target, setTarget] = useState<User | null>(null);
  const [messages, setMessages] = useState<Message[]>([]);
  const [content, setContent] = useState("");
  const [authFailed, setAuthFailed] = useState(false);
  const router = useRouter();
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    api
      .get("/api/me")
      .then((res) => setCurrentUser(res.data))
      .catch(() => setAuthFailed(true));
  }, []);

  useEffect(() => {
    if (!currentUser) return;

    const loadUsers = () => {
      api
        .get("/api/users")
        .then((res) => setUsers(res.data))
        .catch(console.error);
    };

    loadUsers();
    const interval = setInterval(loadUsers, 3000);
    return () => clearInterval(interval);
  }, [currentUser]);

  useEffect(() => {
    if (!currentUser || !target) return;

    const interval = setInterval(async () => {
      try {
        const res = await api.get(`/api/messages/${currentUser.id}/${target.id}`);
        const data: Message[] = res.data;

        const verified = data.map((msg) => {
          const senderUser = msg.sender === currentUser.id ? currentUser : target;
          const isHashEqual = hashMessage(msg.content) === msg.content_hash;
          const isSignatureValid = verifySignature(
            msg.content,
            msg.signature_r,
            msg.signature_s,
            senderUser.public_key_x,
            senderUser.public_key_y
          );
          return { ...msg, verified: isHashEqual && isSignatureValid };
        });

        setMessages(verified);
      } catch (err) {
        console.error("Polling failed:", err);
      }
    }, 2000);

    return () => clearInterval(interval);
  }, [currentUser, target]);

  const loadMessages = async (user: User) => {
    setTarget(user);
    const res = await api.get(`/api/messages/${currentUser?.id}/${user.id}`);
    const data: Message[] = res.data;

    const verified = data.map((msg) => {
      const senderUser = msg.sender === currentUser?.id ? currentUser : user;
      const isHashEqual = hashMessage(msg.content) === msg.content_hash;
      const isSignatureValid = verifySignature(
        msg.content,
        msg.signature_r,
        msg.signature_s,
        senderUser.public_key_x,
        senderUser.public_key_y
      );
      return { ...msg, verified: isHashEqual && isSignatureValid };
    });

    setMessages(verified);
  };

  const handleSend = async () => {
    if (!content.trim() || !currentUser || !target) return;

    const privKey = localStorage.getItem("privateKey");
    if (!privKey) {
      alert("Private key not found.");
      return;
    }

    const normalized = normalizeContent(content);
    const hash = hashMessage(normalized);
    const { r, s } = signMessage(normalized, privKey);

    const msg: Omit<Message, "id" | "verified"> = {
      sender: currentUser.id,
      receiver: target.id,
      content: normalized,
      content_hash: hash,
      signature_r: r,
      signature_s: s,
    };

    try {
      const res = await api.post("/api/messages", msg);
      const data: Message = res.data;
      setMessages((prev) => [...prev, { ...data, verified: true }]);
      setContent("");
    } catch (err) {
      console.error(err);
      alert("Failed to send message.");
    }
  };

  const handleLogout = async () => {
    try {
      await api.post("/api/logout");
      localStorage.removeItem("privateKey");
      router.push("/");
    } catch (err) {
      alert("Logout failed");
    }
  };

  if (authFailed) {
    return (
      <div className="flex items-center justify-center h-screen bg-gradient-to-tr from-blue-500 to-rose-500">
        <div className="text-center bg-white p-10 rounded-xl shadow-lg">
          <h1 className="text-2xl font-bold text-blue-600 mb-4">
            You must log in first!
          </h1>
          <Button onClick={() => router.push("/login")}>Login here</Button>
        </div>
      </div>
    );
  }

  if (!currentUser) return null; 

  return (
    <div className="flex h-screen bg-gradient-to-tr from-blue-500 to-rose-500 p-6">
      <div className="w-1/3 border-r rounded-xl mx-2 overflow-y-auto p-4 bg-white">
        <div className="flex justify-between items-center mb-4">
          <h2 className="font-bold text-3xl text-blue-600">Contacts</h2>
          <Button variant="outline" size="sm" onClick={handleLogout}>
            Logout
          </Button>
        </div>
        <div className="text-lg font-semibold mb-2">
          Welcome, <span className="font-bold text-blue-600">{currentUser.username}!</span>
        </div>
        {users.map((u) => (
          <div
            key={u.id}
            className={`cursor-pointer text-2xl p-4 border-2 my-4 rounded-xl transition-all duration-150 
              ${u.id === target?.id ? "bg-blue-100 font-semibold" : "hover:bg-gray-100"}`}
            onClick={() => loadMessages(u)}
          >
            {u.username}
          </div>
        ))}
      </div>

      <div className="flex-1 flex flex-col p-4 mx-2 bg-white rounded-xl">
        <div className="flex-1 overflow-y-auto border-2 p-4 rounded-md space-y-2">
          {messages.map((msg, idx) => (
            <div
              key={idx}
              className={`max-w-md p-2 rounded-sm break-words border-2 whitespace-pre-wrap ${
                msg.sender === currentUser?.id
                  ? "ml-auto bg-blue-100 text-right"
                  : "mr-auto bg-gray-100"
              }`}
            >
              <div className="text-xl p-2">
                <b>{msg.sender === currentUser?.id ? "You" : target?.username}:</b>{" "}
                {msg.content}
              </div>
              <div
                className={`text-md font-semibold mt-1 ${
                  msg.verified ? "text-green-500" : "text-red-500"
                }`}
              >
                {msg.verified ? "✅ Verified" : "❌ Corrupted"}
              </div>
            </div>
          ))}
        </div>

        <div className="flex gap-2 mt-4">
          <Input
            value={content}
            onChange={(e) => setContent(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleSend()}
            placeholder="Type a message"
            className="flex-1 rounded-md border-2"
          />
          <Button onClick={handleSend}>Send</Button>
        </div>
      </div>
    </div>
  );
}
