# pkit - PKI Lifecycle Management Toolkit

`pkit` is a complete internal Public Key Infrastructure (PKI) lifecycle management CLI tool. It provides comprehensive management of cryptographic keys, X.509 certificates, Certificate Signing Requests (CSRs), and Certificate Revocation Lists (CRLs) with a SQLite-backed persistent database and OS keyring integration.

---

## Features

- **Key Management:** Generate, inspect, list, export, and verify cryptographic key pairs (RSA, ECDSA, Ed25519)
- **Certificate Management:** Generate Root CAs, Intermediate CAs, and Leaf certificates; inspect, validate, verify chains, revoke, rotate, and delete certificates
- **CSR Management:** Generate, inspect, sign, and export Certificate Signing Requests
- **CRL Management:** Generate, inspect, verify, and export Certificate Revocation Lists
- **Secure Storage:** Private keys are encrypted using AES-GCM with a master key stored in the OS keyring
- **Export Formats:** PEM, DER, PKCS#12, and PKCS#7 support

---

## Installation

```bash
go install github.com/tassok-wasi/pkit@latest
```

---

## Getting Started

### 1. Initialize the Application

```bash
pkit init
```

This creates the database (`~/.pkit/pkit.db`) and generates a master key stored in your OS keyring.

### 2. Generate a Key Pair

Before creating certificates, you need a cryptographic key pair:

```bash
pkit key generate --type ed25519 --name "Root CA Key"
```

**Available key types:** `rsa-2048`, `rsa-4096`, `ecdsa-224`, `ecdsa-256`, `ecdsa-384`, `ecdsa-521`, `ed25519`

---

## Key Management (`pkit key`)

### List Keys

```bash
pkit key list
pkit key list --limit 10 --offset 5   # Pagination
```

### Inspect a Key

```bash
pkit key inspect 1                    # Basic info
pkit key inspect 1 --validate         # With cryptographic validation
```

### Export a Key Pair

```bash
# PEM format (decrypted)
pkit key export 1 --path ./mykey --format pem

# DER format
pkit key export 1 --path ./mykey --format der

# Encrypted blob (stored encrypted as in database)
pkit key export 1 --path ./mykey --blob
```

### Delete a Key

```bash
pkit key delete 1
```

---

## Certificate Management (`pkit cert`)

### Generate Certificates

#### Root CA (Self-Signed)

```bash
pkit cert generate ca \
  --cn "Example Root CA" \
  --org "Example Corp" \
  --c US \
  --ttl 10y \
  --ku cert-sign,crl-sign \
  --kid 1
```

**Key Usage (--ku) options:** `digital-signature`, `content-commitment`, `key-encipherment`, `data-encipherment`, `key-agreement`, `cert-sign`, `crl-sign`, `encipher-only`, `decipher-only`

#### Intermediate CA

```bash
pkit cert generate ica \
  --cn "Example Intermediate CA" \
  --org "Example Corp" \
  --ttl 5y \
  --ku cert-sign,crl-sign \
  --eku server-auth,client-auth \
  --path-len 0 \
  --iss 1 \
  --kid 2
```

**Extended Key Usage (--eku) options:** `any`, `server-auth`, `client-auth`, `code-signing`, `email-protection`, `time-stamping`, `ocsp-signing`

#### Leaf Certificate

```bash
pkit cert generate leaf \
  --cn "api.example.com" \
  --org "Example Corp" \
  --ttl 1y \
  --dns api.example.com,www.example.com \
  --ip 192.168.1.100 \
  --uri https://example.com \
  --ku digital-signature,key-encipherment \
  --eku server-auth,client-auth \
  --iss 2 \
  --kid 3
```

### List Certificates

```bash
pkit cert list
pkit cert list --status ACTIVE --type LEAF
pkit cert list --limit 20 --offset 10
```

### Read Raw PEM Data

```bash
pkit cert read 1
```

### Inspect Certificate Details

```bash
pkit cert inspect 1                      # Basic inspection
pkit cert inspect 1 --fingerprint        # Show SHA-1/SHA-256 fingerprints
pkit cert inspect 1 --key-usages         # Show key usage flags
pkit cert inspect 1 --extensions         # Show extended key usage
pkit cert inspect 1 --json               # JSON output
```

### Compare Two Certificates

```bash
pkit cert diff 1 2
```

### Validate Certificate (Sanity Checks)

```bash
pkit cert validate 1
```

### Verify Certificate Chain

```bash
pkit cert verify 1
```

### Revoke a Certificate

```bash
pkit cert revoke 1 --reason key-compromise
```

**Reason options:** `unspecified`, `key-compromise`, `ca-compromise`, `affiliation-changed`, `superseded`, `cessation-of-operation`, `certificate-hold`, `remove-from-crl`, `privilege-withdrawn`, `a-a-compromise`

### Rotate a Certificate (Replace with New Key)

```bash
pkit cert rotate 1 --kid 4
```

### Export Certificates

```bash
# Single certificate (PEM)
pkit cert export leaf 1 --path ./cert --format pem

# Single certificate (DER)
pkit cert export leaf 1 --path ./cert --format der

# Full chain (PEM)
pkit cert export chain 1 --path ./chain --format pem

# Full chain (PKCS#7)
pkit cert export chain 1 --path ./chain --format pkcs7

# PKCS#12 bundle (with private key)
pkit cert export bundle 1 --path ./bundle --format pkcs12 --pass-phrase "secret"
```

### Delete a Certificate

```bash
pkit cert delete 1
```

---

## CSR Management (`pkit csr`)

### Generate a CSR

```bash
pkit csr generate \
  --cn "app.example.com" \
  --org "Example Corp" \
  --dns app.example.com,api.example.com \
  --ip 10.0.0.1 \
  --type ed25519 \
  --kid 5
```

### List CSRs

```bash
pkit csr list
pkit csr list --status PENDING
pkit csr list --limit 10
```

### Read Raw CSR PEM

```bash
pkit csr read 1
```

### Inspect CSR Details

```bash
pkit csr inspect 1
```

### Verify CSR (Self-Signature & Key Integrity)

```bash
pkit csr verify 1
```

### Sign a CSR

```bash
pkit csr sign 1 \
  --iss 2 \
  --type LEAF \
  --ttl 1y \
  --ku digital-signature,key-encipherment \
  --eku server-auth,client-auth
```

### Export a CSR

```bash
# PEM format
pkit csr export 1 --path ./csr --format pem

# DER format
pkit csr export 1 --path ./csr --format der
```

---

## CRL Management (`pkit crl`)

### Generate a CRL

```bash
pkit crl generate --iss 1 --ttl 168h
```

### List CRLs

```bash
pkit crl list --iss 1
pkit crl list --iss 1 --limit 10 --offset 5
```

### Read Raw CRL PEM

```bash
pkit crl read 1
```

### Inspect CRL Details

```bash
pkit crl inspect 1
```

### Verify CRL Signature

```bash
pkit crl verify 1
```

### Validate CRL (Sanity Checks)

```bash
pkit crl validate 1
```

### Compare Two CRLs

```bash
pkit crl diff 1 2
```

### Export a CRL

```bash
# PEM format
pkit crl export 1 --path ./crl --format pem

# DER format
pkit crl export 1 --path ./crl --format der
```

---

## Global Flags

| Flag | Description |
|------|-------------|
| `--help` | Show help for any command |

---

## Database Schema

`pkit` uses SQLite with the following tables:
- `keys` - Cryptographic key pairs (private keys stored encrypted)
- `certificates` - X.509 certificates
- `csrs` - Certificate Signing Requests
- `crls` - Certificate Revocation Lists

---

## Security Notes

- **Private keys are encrypted** using AES-256-GCM before being stored in the database
- **Master key** is stored in the OS keyring (macOS Keychain, Windows Credential Manager, or Linux Secret Service)
- **Sensitive files** are written with `0600` permissions
- **Database** uses WAL journal mode and foreign key constraints

---

## License

Apache License 2.0. See `LICENSE` for details.

---

## Author

Tassok Imam Wasi
