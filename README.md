# go-safety

Encrypt and decrypt metadata (email + JSON payload) from the command line. Uses AES-256-GCM with Argon2 key derivation — no plaintext secrets, no config files, just a seed you can store anywhere.

## Quick start

```bash
# Clone and build
git clone https://github.com/Damoz1606/go-safety.git
cd go-safety
go build -o go-safety ./cmd/cli

# Encrypt
./go-safety -mode=encrypt \
  -email="user@example.com" \
  -passkey="my-secret" \
  -metadata='{"project":"Alpha","keys":3}'

# Output:
# Seed: <base64-encoded ciphertext>

# Decrypt
./go-safety -mode=decrypt \
  -seed="<seed-from-above>" \
  -passkey="my-secret"

# Output:
# Email:    user@example.com
# Metadata: {
#   "project": "Alpha",
#   "keys": 3
# }
```

Requirements: **Go 1.25+**. No external runtime dependencies beyond what's vendored.

## How it works

| Step | What happens |
|------|-------------|
| Key derivation | Argon2id stretches your passkey with a random 16-byte salt. |
| Encryption | AES-256-GCM encrypts the serialized `{email, metadata}` JSON. A random 12-byte nonce is generated per operation. |
| Output | Salt, nonce, and ciphertext are packed together and base64-encoded into a single seed string. |

The seed is self-contained — you only need the seed and the passkey to decrypt. No key files, no environment variables, no databases.

## Commands

| Flag | Required | Description |
|------|----------|-------------|
| `-mode` | Yes | `encrypt` or `decrypt` |
| `-email` | Encrypt only | Email address to embed in the payload |
| `-passkey` | Yes | Passphrase for key derivation |
| `-metadata` | Encrypt only | Valid JSON string to protect |
| `-seed` | Decrypt only | Base64 seed from a previous encryption |

The `-metadata` flag must be valid JSON — objects, arrays, and primitive values are all accepted.

## Architecture

```
cmd/cli/main.go              → entry point
internal/safety/             → domain model (Metadata)
  application/               → use cases (encrypt, decrypt)
  port/                      → Cipher interface
  infrastructure/
    cipher/                  → AES-GCM + Argon2 implementation
    cli/                     → flag parsing and dispatch
```

Follows clean/hexagonal architecture: the application layer depends only on the `port.Cipher` interface, making the crypto implementation swappable and testable in isolation.

## Testing

```bash
# Run all tests
go test ./...

# With coverage
go test -cover ./internal/...
```

The test suite covers every layer:

- **Domain** — metadata construction, serialization, round-trip integrity.
- **Application** — encrypt/decrypt flows with a mocked cipher, error propagation.
- **Infrastructure** — cipher round-trips (valid, wrong passkey, tampered seed), determinism, custom Argon2 configs.
- **CLI** — argument validation for both modes.

## License

MIT
