DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS academics;
DROP TABLE IF EXISTS academic_shares;

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

CREATE TABLE academic_shares (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        academic_id INTEGER NOT NULL REFERENCES academics (id),
        dosen_wali_id INTEGER NOT NULL REFERENCES users (id),
        share_x INTEGER NOT NULL,
        share_y INTEGER NOT NULL,
        requested_by INTEGER NOT NULL REFERENCES users (id),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);