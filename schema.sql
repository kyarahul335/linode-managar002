CREATE TABLE IF NOT EXISTS keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_key TEXT UNIQUE NOT NULL,
    total_limit INTEGER DEFAULT 0,
    available_limit INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_id INTEGER,
    account_name TEXT NOT NULL,
    token TEXT NOT NULL,
    FOREIGN KEY (key_id) REFERENCES keys (id)
);