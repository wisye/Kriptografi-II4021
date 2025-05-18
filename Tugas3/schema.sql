DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS messages;

CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        public_key_x TEXT NOT NULL,
        public_key_y TEXT NOT NULL,
);

CREATE TABLE messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender TEXT NOT NULL,
        receiver TEXT NOT NULL,
        content TEXT NOT NULL,
        content_hash TEXT NOT NULL,
        signature_r TEXT NOT NULL,
        signature_s TEXT NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);