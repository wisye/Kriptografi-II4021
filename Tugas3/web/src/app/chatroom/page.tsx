"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export default function Home() {
  const router = useRouter();
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
      { id: 3, sender: username, content: "Oops corrupted! This is a very long message meant to test the wrapping behavior inside a chat bubble. It should not overflow or break the layout, and must stay readable.", verified: false },
    ]);
  };

  const sendMessage = () => {
    if (!content.trim()) return;
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
    <div className={`text-md font-semibold mt-1 ${msg.verified ? "text-green-500" : "text-red-500"}`}>
      {msg.verified ? "✅ Verified" : "❌ Corrupted"}
    </div>
  );

  const handleKeyPress = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };

  return (
    <div className="flex h-screen bg-gradient-to-tr from-blue-300 to-white-500 p-6">
      <div className="w-1/3 border-r rounded-xl mx-2 overflow-y-auto p-4 bg-white">
        <h2 className="font-bold text-2xl flex justify-center items-center mb-2">Contacts</h2>
        {users.map((u) => (
          <div
            key={u.username}
            className={`cursor-pointer text-2xl p-4 border-2 my-4 rounded-xl transition-all duration-150 
              ${u.username === target ? "bg-blue-100 font-semibold" : "hover:bg-gray-100"}`}
            onClick={() => loadMessages(u.username)}
          >
            {u.username}
          </div>
        ))}
      </div>
      <div className="flex-1 flex flex-col p-4 mx-2 bg-white rounded-xl">
        <div className="flex-1 overflow-y-auto border p-4 rounded space-y-2">
          {messages.map((msg) => (
            <div
              key={msg.id}
              className={`max-w-md p-2 rounded-xl break-words whitespace-pre-wrap ${
                msg.sender === "you" ? "ml-auto bg-blue-100 text-right" : "mr-auto bg-gray-100"
              }`}
            >
              <div className="text-xl p-2">
                <b>{msg.sender}:</b> {msg.content}
              </div>
              {renderStatus(msg)}
            </div>
          ))}
        </div>
        <div className="flex gap-2 mt-4">
          <Input
            value={content}
            onChange={e => setContent(e.target.value)}
            onKeyDown={handleKeyPress}
            placeholder="Type a message"
            className="flex-1"
          />
          <Button onClick={sendMessage}>Send</Button>
        </div>
      </div>
    </div>
  );
}
