CREATE TABLE IF NOT EXISTS keys (
    id TEXT PRIMARY KEY,
    key_type TEXT NOT NULL,       -- e.g., 'RSA-2048', 'ECDSA-P256', 'ED25519'
    public_key TEXT NOT NULL,
    private_key BLOB NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS certificates (
    id TEXT PRIMARY KEY,
    key_id TEXT NOT NULL,
    serial_number TEXT UNIQUE NOT NULL,
    cert_type TEXT NOT NULL,            -- 'ROOT_CA', 'INTERMEDIATE_CA', 'LEAF'
    parent_id TEXT,
    subject_json TEXT NOT NULL,
    issuer_json TEXT NOT NULL,
    not_before DATETIME NOT NULL,
    not_after DATETIME NOT NULL,
    pem_content TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (key_id) REFERENCES keys(id) ON DELETE RESTRICT,
    FOREIGN KEY (parent_id) REFERENCES certificates(id) ON DELETE SET NULL
);
