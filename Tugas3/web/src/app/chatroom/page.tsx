"use client";

import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import api from "@/lib/api";
import { formatTimestamp } from "@/lib/time";
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
  timestamp?: string;
  verified?: boolean;
  typing?: boolean;
}

export default function Chatroom() {
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [users, setUsers] = useState<User[]>([]);
  const [target, setTarget] = useState<User | null>(null);
  const [messages, setMessages] = useState<Message[]>([]);
  const [content, setContent] = useState("");
  const [authFailed, setAuthFailed] = useState(false);
  const [typingUser, setTypingUser] = useState<string | null>(null);

  const router = useRouter();
  const wsRef = useRef<WebSocket | null>(null);
  const typingTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const chatBottomRef = useRef<HTMLDivElement>(null);

  const toIsoUtc = (ts?: string) => {
    if (!ts) return ts as unknown as string;
    if (/[Z+\-]/.test(ts)) return ts; 
    if (ts.includes("T")) return `${ts}Z`;
    return ts.replace(" ", "T") + "Z";
  };

  // Scroll
  useEffect(() => {
    chatBottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  //get user
  useEffect(() => {
    api
      .get("/api/me")
      .then((res) => setCurrentUser(res.data))
      .catch(() => setAuthFailed(true));
  }, []);

  useEffect(() => {
    if (!currentUser) return;
    const loadUsers = () =>
      api.get("/api/users").then((res) => setUsers(res.data)).catch(console.error);
    loadUsers();
    const interval = setInterval(loadUsers, 3000);
    return () => clearInterval(interval);
  }, [currentUser]);

  // webscvokert
  useEffect(() => {
    if (!currentUser) return;

    const ws = new WebSocket(`ws://103.59.160.119:4121/ws/${currentUser.id}`);

    ws.onopen = () => console.log("WebSocket connected");

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);

        if (data.typing && target && data.sender === target.id) {
          setTypingUser(data.username);
          if (typingTimeoutRef.current) clearTimeout(typingTimeoutRef.current);
          typingTimeoutRef.current = setTimeout(() => setTypingUser(null), 2000);
          return;
        }

        data.timestamp = toIsoUtc(data.timestamp);

        const senderUser =
          data.sender === currentUser.id ? currentUser : users.find((u) => u.id === data.sender);

        const isHashEqual = hashMessage(data.content) === data.content_hash;
        const isSignatureValid =
          senderUser &&
          verifySignature(
            data.content,
            data.signature_r,
            data.signature_s,
            senderUser.public_key_x,
            senderUser.public_key_y,
          );

        setMessages((prev) => [
          ...prev,
          { ...data, verified: isHashEqual && isSignatureValid },
        ]);

        if (Notification.permission === "granted") {
          new Notification(
            `New message from ${data.sender === currentUser.id ? "you" : senderUser?.username}`,
          );
        }
      } catch (e) {
        console.error("Invalid WebSocket message", e);
      }
    };

    ws.onclose = () => console.log("WebSocket disconnected");
    ws.onerror = (err) => console.error("WebSocket error", err);

    wsRef.current = ws;
    return () => ws.close();
  }, [currentUser, target, users]);

  // load msg
  const loadMessages = async (user: User) => {
    setTarget(user);
    const res = await api.get(`/api/messages/${currentUser?.id}/${user.id}`);
    const data: Message[] = res.data;

    const verified = data.map((msg) => {
      msg.timestamp = toIsoUtc(msg.timestamp);

      const senderUser = msg.sender === currentUser?.id ? currentUser : user;
      const isHashEqual = hashMessage(msg.content) === msg.content_hash;
      const isSignatureValid = verifySignature(
        msg.content,
        msg.signature_r,
        msg.signature_s,
        senderUser.public_key_x,
        senderUser.public_key_y,
      );
      return { ...msg, verified: isHashEqual && isSignatureValid };
    });

    setMessages(verified);
  };
  // send msg
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

    const isHashEqual = hashMessage(normalized) === hash;
    const isSignatureValid = verifySignature(
      normalized,
      r,
      s,
      currentUser.public_key_x,
      currentUser.public_key_y,
    );

    const nowUtcIso = new Date().toISOString();

    const msg: Message = {
      sender: currentUser.id,
      receiver: target.id,
      content: normalized,
      content_hash: hash,
      signature_r: r,
      signature_s: s,
      timestamp: nowUtcIso,
      verified: isHashEqual && isSignatureValid,
    };

    setMessages((prev) => [...prev, msg]);
    setContent("");

    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(msg));
    } else {
      alert("WebSocket not connected.");
    }
  };
// typing 
  const handleTyping = () => {
    if (!wsRef.current || wsRef.current.readyState !== WebSocket.OPEN || !currentUser || !target) return;
    wsRef.current.send(
      JSON.stringify({ typing: true, sender: currentUser.id, receiver: target.id, username: currentUser.username }),
    );
  };

  const handleLogout = async () => {
    try {
      await api.post("/api/logout");
      localStorage.removeItem("privateKey");
      router.push("/");
    } catch {
      alert("Logout failed");
    }
  };

  useEffect(() => {
    if (Notification.permission !== "granted") Notification.requestPermission();
  }, []);

  if (authFailed) {
    return (
      <div className="flex items-center justify-center h-screen bg-gradient-to-tr from-blue-500 to-rose-500">
        <div className="text-center bg-white p-10 rounded-xl shadow-lg">
          <h1 className="text-2xl font-bold text-blue-600 mb-4">
            You must log in first or you have already logged in on another device!
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
                <b>{msg.sender === currentUser?.id ? "You" : target?.username}:</b> {msg.content}
              </div>
              <div className="text-xs text-gray-500">
                {msg.timestamp && formatTimestamp(msg.timestamp)}
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
          {typingUser && (
            <div className="text-sm text-gray-500 italic">
              {typingUser} is typing...
            </div>
          )}
          <div ref={chatBottomRef} /> 
        </div>                          


        <div className="flex gap-2 mt-4">
          <Input
            value={content}
            onChange={(e) => {
              setContent(e.target.value);
              handleTyping();
            }}
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
