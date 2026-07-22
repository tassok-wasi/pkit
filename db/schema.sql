PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    algorithm TEXT NOT NULL,
    private_key_pem TEXT NOT NULL,
    public_key_pem TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS certificates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    serial_number TEXT NOT NULL UNIQUE,
    common_name TEXT NOT NULL,
    type TEXT NOT NULL,
    key_id INTEGER NOT NULL,
    issuer_serial_number TEXT,
    not_before DATETIME NOT NULL,
    not_after DATETIME NOT NULL,
    skid TEXT NOT NULL,
    akid TEXT NOT NULL,
    is_revoked INTEGER DEFAULT 0,
    revocation_reason INTEGER,
    revocation_time DATETIME,
    certificate_pem TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (key_id) REFERENCES keys(id) ON DELETE RESTRICT,
    FOREIGN KEY (issuer_serial_number) REFERENCES certificates(serial_number) ON DELETE SET NULL,
    CHECK (type IN ('CA', 'INTERMEDIATE', 'LEAF')),
    CHECK (is_revoked IN (0, 1)),
    CHECK (status IN ('ACTIVE', 'REVOKED', 'EXPIRED')),
    CHECK (status = 'REVOKED' AND is_revoked = 1)
);

CREATE TABLE IF NOT EXISTS csrs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    common_name TEXT NOT NULL,
    key_id INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING',
    csr_pem TEXT NOT NULL,
    certificate_id INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (key_id) REFERENCES keys(id) ON DELETE RESTRICT,
    FOREIGN KEY (certificate_id) REFERENCES certificates(id) ON DELETE SET NULL,
    CHECK (status IN ('PENDING', 'SIGNED', 'REJECTED'))
);

CREATE TABLE IF NOT EXISTS crls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    crl_number INTEGER NOT NULL,
    issuer_id INTEGER NOT NULL,
    this_update DATETIME NOT NULL,
    next_update DATETIME NOT NULL,
    crl_pem TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (issuer_id) REFERENCES certificates(id) ON DELETE RESTRICT
);

-- Core Indexes for Standard Operation Filtering
CREATE INDEX IF NOT EXISTS idx_certs_serial ON certificates(serial_number);
CREATE INDEX IF NOT EXISTS idx_certs_revoked ON certificates(is_revoked);
CREATE INDEX IF NOT EXISTS idx_certs_cn ON certificates(common_name);

-- CSR Optimization Indexes
CREATE INDEX IF NOT EXISTS idx_csrs_status ON csrs(status);
CREATE INDEX IF NOT EXISTS idx_csrs_cn ON csrs(common_name);

-- O(1) Optimization Indexes for X509 Hierarchy Mapping and Verification
CREATE INDEX IF NOT EXISTS idx_certs_skid ON certificates(skid);
CREATE INDEX IF NOT EXISTS idx_crls_issuer ON crls(issuer_id);
