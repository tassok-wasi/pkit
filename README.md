# pkit

`pkit` is a local PKI command-line tool for working with keys, CSRs, certificates, and CRLs.

The idea behind it is simple: sometimes you do not need a full certificate platform or an external CA service. You just need a solid local tool that can help you issue certificates, inspect what you already have, revoke them when needed, and export the right artifacts in standard formats.

`pkit` stores its working state locally in SQLite and uses the OS keyring to protect the master key used for private key encryption.

---

## What it can do

`pkit` is split into four main areas:

- `key` — generate, inspect, verify, read, list, and export key pairs
- `csr` — generate, inspect, verify, sign, list, read, and export CSRs
- `cert` — generate, inspect, validate, verify, diff, revoke, rotate, list, read, and export certificates
- `crl` — generate, inspect, validate, verify, diff, list, read, and export CRLs

In short, it covers the core lifecycle of a small internal PKI.

---

## Setup

Build the binary:

```bash
go build -o pkit .
```

Initialize the local workspace once:

```bash
./pkit init
```

This creates the local application directory and database under:

```text
~/.pkit/
```

Database path:

```text
~/.pkit/pkit.db
```

After that, the rest of the commands are ready to use.

---

## A normal workflow

A typical flow looks like this:

1. generate a key pair
2. issue a root CA
3. issue an intermediate CA if needed
4. issue a leaf certificate
5. inspect and verify it
6. revoke it if necessary
7. generate a CRL

That is really the heart of the tool.

---

## Quick examples

### Generate a key pair

```bash
./pkit key generate --name root-key --type ed25519
./pkit key generate --name ica-key --type ed25519
./pkit key generate --name leaf-key --type ed25519
```

### Create a root CA

```bash
./pkit cert generate ca \
  --cn "Example Root CA" \
  --kid 1 \
  --ttl 10y
```

### Create an intermediate CA

```bash
./pkit cert generate ica \
  --cn "Example Intermediate CA" \
  --kid 2 \
  --iss 1 \
  --ttl 2y \
  --path-len 1
```

### Create a leaf certificate

```bash
./pkit cert generate leaf \
  --cn "api.example.internal" \
  --kid 3 \
  --iss 2 \
  --ttl 365d \
  --dns api.example.internal \
  --dns example.internal
```

### Inspect and verify a certificate

```bash
./pkit cert inspect 3
./pkit cert inspect 3 --fingerprint
./pkit cert validate 3
./pkit cert verify 3
```

### Revoke a certificate

```bash
./pkit cert revoke 3 --reason key-compromise
```

### Generate a CRL

```bash
./pkit crl generate --iss 2 --ttl 7d
./pkit crl inspect 1
./pkit crl verify 1
```

---

## Working with CSRs

If you want a CSR-based flow instead of issuing directly, that is supported too.

### Generate a CSR

```bash
./pkit csr generate \
  --cn service.example.internal \
  --kid 3 \
  --type ed25519 \
  --dns service.example.internal
```

### Inspect and verify it

```bash
./pkit csr list
./pkit csr inspect 1
./pkit csr verify 1
```

### Sign it into a certificate

```bash
./pkit csr sign 1 --type LEAF --iss 2 --ttl 365d
```

---

## Exporting artifacts

`pkit` can export objects in the formats you would expect.

### Certificates

```bash
./pkit cert export leaf 3 --format pem --path ./out
./pkit cert export leaf 3 --format der --path ./out/server.der
```

### Certificate chains

```bash
./pkit cert export chain 3 --format pem --path ./out
./pkit cert export chain 3 --format pkcs7 --path ./out
```

### Certificate bundles

```bash
./pkit cert export bundle 3 --format pkcs12 --pass-phrase "changeit" --path ./out
```

### Keys

```bash
./pkit key export 3 --format pem --path ./keys
./pkit key export 3 --format der --path ./keys
./pkit key export 3 --format pem --blob --path ./keys
```

### CRLs

```bash
./pkit crl export 1 --format pem --path ./out
./pkit crl export 1 --format der --path ./out/example.crl.der
```

---

## Useful commands to know

### Certificates

```bash
./pkit cert list
./pkit cert read 3
./pkit cert diff 3 4
./pkit cert rotate 3 --kid 4 --iss 2
```

### Keys

```bash
./pkit key list
./pkit key read 3
./pkit key inspect 3 --validate
./pkit key verify 3
```

### CSRs

```bash
./pkit csr list --status PENDING
./pkit csr read 1
./pkit csr export 1 --format pem --path ./out
```

### CRLs

```bash
./pkit crl list
./pkit crl read 1
./pkit crl validate 1
./pkit crl diff 1 2
```

---

## A few practical notes

- Most commands work by database ID, so `list` is usually the first thing you run.
- Trust-chain verification is done against certificates stored in the local database.
- Private keys are encrypted before storage.
- Exported key material is handled more carefully than public certificate artifacts.
- TTL values use the formats implemented in the code: `h`, `d`, and `y`.

---

## Development

Run the full test suite with:

```bash
go test ./...
```

Main directories:

- `cmd/` — CLI commands
- `db/` — schema and generated queries
- `domain/` — PKI lifecycle logic
- `utils/` — crypto, parsing, validation, and helpers
- `testutil/` — test support code

---

## License

Apache License 2.0. See `LICENSE` for details.
