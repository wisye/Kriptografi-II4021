"use client";

import { useState } from "react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export default function Home() {
  const [users] = useState([
    { username: "alice" },
    { username: "bob" },
    { username: "charlie" },
  ]);

  const [messages, setMessages] = useState<any[]>([]);
  const [target, setTarget] = useState("");
  const [content, setContent] = useState("");

  const loadMessages = (username: string) => {
    setTarget(username);
    setMessages([
      { id: 1, sender: username, content: "Hello there!", verified: true },
      { id: 2, sender: "you", content: "Hi! How are you?", verified: true },
      { id: 3, sender: username, content: "Oops corrupted!", verified: false },
    ]);
  };

  const sendMessage = () => {
    const newMsg = {
      id: Date.now(),
      sender: "you",
      content,
      verified: true,
    };
    setMessages([...messages, newMsg]);
    setContent("");
  };

  const renderStatus = (msg: any) => (
    <span className={`ml-2 text-xs font-semibold ${msg.verified ? "text-green-500" : "text-red-500"}`}>
      {msg.verified ? "✅ Verified" : "❌ Corrupted"}
    </span>
  );

  return (
    <div className="flex h-screen">
      <div className="w-1/3 border-r overflow-y-auto p-4">
        <h2 className="font-bold text-6xl flex justify-center items-center mb-2">Contacts</h2>
          {users.map((u) => (
          <div
            key={u.username}
            className={`cursor-pointer text-2xl border-2 my-4 p-2 rounded transition-all duration-150 
              ${u.username === target ? "bg-blue-100 font-semibold" : "hover:bg-gray-100"}`}
            onClick={() => loadMessages(u.username)}
          >
            {u.username}
          </div>
        ))}

      </div>
      <div className="flex-1 flex flex-col p-4">
        <div className="flex-1 overflow-y-auto border p-4 rounded space-y-2">
          {messages.map((msg) => (
            <div
              key={msg.id}
              className={`max-w-xs p-2 rounded-lg ${
                msg.sender === "you" ? "ml-auto bg-blue-100 text-right" : "mr-auto bg-gray-100"
              }`}
            >
              <div className="text-sm">
                <b>{msg.sender}:</b> {msg.content} {renderStatus(msg)}
              </div>
            </div>
          ))}
        </div>
        <div className="flex gap-2 mt-4">
          <Input value={content} onChange={e => setContent(e.target.value)} placeholder="Type a message" className="flex-1" />
          <Button onClick={sendMessage}>Send</Button>
        </div>
      </div>
    </div>
  );
}
