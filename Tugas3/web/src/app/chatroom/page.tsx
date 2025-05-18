"use client";

import { useEffect, useRef, useState } from "react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import api from "@/lib/api";
import {
  signMessage,
  verifySignature,
  hashMessage,
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

  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    api.get("/api/me")
      .then((res) => setCurrentUser(res.data))
      .catch(console.error);
  }, []);

  useEffect(() => {
    if (!currentUser) return;
    api.get("/api/users")
      .then((res) => setUsers(res.data))
      .catch(console.error);
  }, [currentUser]);

  useEffect(() => {
    if (!currentUser) return;

    const sessionToken = document.cookie
      .split("; ")
      .find((row) => row.startsWith("session_token="))
      ?.split("=")[1];

    if (!sessionToken) return;

    const ws = new WebSocket(
      `ws://localhost:8000/ws/${currentUser.id}?token=${sessionToken}`
    );

    ws.onmessage = async (event) => {
      const msg = JSON.parse(event.data);
      const { sender, content, content_hash, signature_r, signature_s } = msg;
      const senderUser = users.find((u) => u.id === sender);
      if (!senderUser) return;

      const valid = verifySignature(
        content,
        signature_r,
        signature_s,
        senderUser.public_key_x,
        senderUser.public_key_y
      );

      setMessages((prev) => [...prev, { ...msg, verified: valid }]);
    };

    wsRef.current = ws;
    return () => ws.close();
  }, [currentUser, users]);

  const loadMessages = async (user: User) => {
    setTarget(user);
    const res = await api.get(`/api/messages/${currentUser?.id}/${user.id}`);
    const data: Message[] = res.data;

    const verified = data.map((msg) => {
      const senderUser =
        msg.sender === currentUser?.id ? currentUser : user;
      const valid = verifySignature(
        msg.content,
        msg.signature_r,
        msg.signature_s,
        senderUser!.public_key_x,
        senderUser!.public_key_y
      );
      return { ...msg, verified: valid };
    });

    setMessages(verified);
  };

  const handleSend = () => {
    if (!content.trim() || !currentUser || !target) return;

    const hash = hashMessage(content);
    const privKey = localStorage.getItem("privateKey");
    if (!privKey) {
      alert("Private key not found.");
      return;
    }

    const { r, s } = signMessage(content, privKey);

    const msg: Message = {
      sender: currentUser.id,
      receiver: target.id,
      content,
      content_hash: hash,
      signature_r: r,
      signature_s: s,
    };

    wsRef.current?.send(JSON.stringify(msg));
    setMessages((prev) => [...prev, { ...msg, verified: true }]);
    setContent("");
  };

  return (
    <div className="flex h-screen bg-gradient-to-tr from-blue-500 to-rose-500 p-6">
      <div className="w-1/3 border-r rounded-xl mx-2 overflow-y-auto p-4 bg-white">
        <h2 className="font-bold text-3xl flex justify-center text-blue-600 items-center mb-2">
          Contacts
        </h2>
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
                <b>
                  {msg.sender === currentUser?.id
                    ? "you"
                    : target?.username}
                  :
                </b>{" "}
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
