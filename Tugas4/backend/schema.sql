DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS transcripts;
DROP TABLE IF EXISTS courses;

CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL UNIQUE,
        password TEXT NOT NULL,
        role TEXT NOT NULL CHECK (role IN ('Mahasiswa', 'Dosen Wali', 'Ketua Program Studi')),
        major TEXT NOT NULL CHECK (major IN ('IF', 'STI'))
);

CREATE TABLE transcripts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nim TEXT NOT NULL REFERENCES users (username),
        name TEXT,
        encrypted_data TEXT,
        ipk REAL,
        signature TEXT,
        created_by INTEGER REFERENCES users (id),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (created_by) REFERENCES users (id)
);

CREATE TABLE courses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        transcript_id INTEGER,
        course_code TEXT NOT NULL,
        course_name TEXT NOT NULL,
        credits INTEGER NOT NULL,
        grade REAL NOT NULL,
        FOREIGN KEY (transcript_id) REFERENCES transcripts (id)
);