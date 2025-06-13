DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS academics;
DROP TABLE IF EXISTS courses;

CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL UNIQUE,
        password TEXT NOT NULL,
        role TEXT NOT NULL CHECK (role IN ('Mahasiswa', 'Dosen Wali', 'Ketua Program Studi')),
        major TEXT NOT NULL CHECK (major IN ('IF', 'STI'))
);

CREATE TABLE academics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nim TEXT NOT NULL REFERENCES users (username),
        name TEXT,
        encrypted_data TEXT,
        encrypted_key TEXT,
        hashed_data TEXT,
        signature TEXT,
        created_by INTEGER REFERENCES users (id),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);