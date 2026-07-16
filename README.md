# certman – Certificate Management Toolkit

**certman** is a command-line tool for generating, inspecting, verifying, and managing X.509 certificates and private keys. It supports **Root CAs**, **Intermediate CAs**, and **Leaf** certificates with flexible key algorithms, custom key usages, and encrypted private keys using the OS keyring.

---

## Features

- **Generate** Root CA, Intermediate CA, and Leaf certificates.
- **Interactive** prompts (TUI) or fully non‑interactive flag‑based workflows.
- **Multiple key types**: RSA (2048/4096), ECDSA (P‑224/256/384/521), and Ed25519.
- **Flexible validity** with TTL in hours (`h`), days (`d`), or years (`y`).
- **Custom key usages** (e.g., `cert-sign`, `digital-signature`) and **extended key usages** (e.g., `server-auth`, `client-auth`).
- **Inspect** certificates and keys with detailed cryptographic metadata.
- **Verify** certificate chains and key‑pair consistency.
- **Encrypt** private keys at rest using AES‑GCM with a master key stored in your OS keyring (Linux, macOS, Windows).
- **Deterministic file organization** – certificates are stored under `~/certman/certificates/`.
- **Read/Write** certificates and keys in PEM format.

---

## Installation

### From source

```bash
git clone https://github.com/yourusername/certman.git
cd certman
go build -o certman .
```

Make sure you have Go 1.21+ installed.

### Using `go install`

```bash
go install github.com/twasiy/certman@latest
```

---

## Quick Start

### 1. Initialise the application

```bash
certman init
```

This creates the directory structure and generates a master encryption key in your OS keyring. The key is used to encrypt private keys when you pass the `--encrypt` flag.

### 2. Create a Root CA

```bash
certman write ca --common-name "My Root CA" --key-type ed25519 --ttl 10y
```

Or interactively:

```bash
certman write ca --it
```

### 3. Create an Intermediate CA

```bash
certman write inter-ca \
  --common-name "My Intermediate CA" \
  --key-type ecdsa-256 \
  --ttl 5y \
  --parent-cert ~/certman/certificates/roots/my_root_ca/my_root_ca.cert \
  --parent-priv-key ~/certman/certificates/roots/my_root_ca/my_root_ca_private_key.pem
```

### 4. Create a Leaf certificate

```bash
certman write leaf \
  --common-name "example.com" \
  --key-type ecdsa-256 \
  --ttl 1y \
  --dns-names example.com,www.example.com \
  --ip-addrs 192.168.1.1 \
  --parent-cert ~/certman/certificates/issued_by/my_root_ca/my_intermediate_ca/my_intermediate_ca.cert \
  --parent-priv-key ~/certman/certificates/issued_by/my_root_ca/my_intermediate_ca/my_intermediate_ca_private_key.pem \
  --encrypt
```

The `--encrypt` flag will encrypt the private key using your master key.

### 5. Inspect a certificate

```bash
certman inspect cert --path ~/certman/certificates/issued_by/my_root_ca/my_intermediate_ca/example.com.cert --fingerprint --extensions
```

### 6. Verify a certificate chain

```bash
certman verify cert --path ./leaf.cert --issuer ./intermediate.cert --root ./root.cert --dns-name example.com
```

### 7. Verify that a private key matches a certificate

```bash
certman verify key --cert ./leaf.cert --key ./leaf_private_key.pem
```

---

## Command Overview

| Command        | Description                                                       |
|----------------|-------------------------------------------------------------------|
| `init`         | Initialise the application and master key in the OS keyring.     |
| `read cert`    | Read a certificate file and print its raw PEM content.           |
| `read key`     | Read a key file and print its PEM (optionally decrypt).          |
| `write ca`     | Generate a Root CA certificate and its key pair.                 |
| `write inter-ca`| Generate an Intermediate CA signed by a parent CA.               |
| `write leaf`   | Generate a Leaf certificate signed by a parent CA.               |
| `inspect cert` | Display detailed certificate metadata (subject, issuer, SAN, etc.).|
| `inspect key`  | Display key algorithm, parameters, and optionally validate.      |
| `verify cert`  | Validate certificate chain, expiration, and DNS/name matching.   |
| `verify key`   | Check if a private key matches a certificate’s public key.        |

Use `--help` with any command for detailed flags.

---

## File Structure

All certificates and keys are stored under `~/certman/certificates/`:

```
~/certman/certificates/
├── roots/                        # Self‑signed Root CAs
│   └── <root_cn>/
│       ├── <root_cn>.cert
│       ├── <root_cn>_private_key.pem
│       └── <root_cn>_public_key.pem
└── issued_by/                    # Certificates issued by a parent
    └── <issuer_cn>/
        └── <subject_cn>/
            ├── <subject_cn>.cert
            ├── <subject_cn>_private_key.pem
            ├── <subject_cn>_public_key.pem
            └── <subject_cn>_fullchain.pem    # (leaf only) certificate + parent chain
```

- `*.cert` – DER certificate encoded in PEM.
- `*_private_key.pem` – private key (PKCS#8, PKCS#1, or EC) optionally encrypted.
- `*_public_key.pem` – public key in PKIX format.
- `*_fullchain.pem` – leaf certificate followed by its parent certificate(s) for easy server deployment.

---

## Security & Encryption

- **Master key**: generated during `init` and stored in the OS keyring (using the [go-keyring](https://github.com/zalando/go-keyring) library). On Linux, this typically uses `gnome‑keyring`, `kwallet`, or the `secret‑service` DBus API.
- **Private key encryption**: when using `--encrypt`, the private key is encrypted with AES‑GCM using the master key. The PEM header becomes `ENCRYPTED PRIVATE KEY` (or similar), preventing unauthorised use.
- **Key usages** are strictly enforced according to the X.509 standard.

---

## Contributing

Contributions are welcome! Please open issues or pull requests on the [GitHub repository](https://github.com/twasiy/certman). Ensure that:

- Code is formatted with `go fmt`.
- Tests (if any) pass.
- Documentation is updated accordingly.

---

## License

This project is licensed under the MIT License – see the [LICENSE](LICENSE) file for details.

---

## Acknowledgements

- Built with [Kong](https://github.com/alecthomas/kong) for CLI parsing.
- Interactive prompts powered by [Huh](https://github.com/charmbracelet/huh).
- Uses [Argon2](https://pkg.go.dev/golang.org/x/crypto/argon2) for hashing (future use) and standard Go crypto libraries.
