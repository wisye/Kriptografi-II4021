DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS messages;

CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        hashed_pass TEXT NOT NULL
        private_key TEXT NOT NULL,
        public_key TEXT NOT NULL,
);

CREATE TABLE messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_usn TEXT NOT NULL,
        receiver_usn TEXT NOT NULL,
        content TEXT NOT NULL,
        hashed_content TEXT NOT NULL,
        signature TEXT NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);