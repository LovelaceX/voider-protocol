# ∅ voider-protocol

**Zero-knowledge, quantum-resistant encryption for ephemeral file sharing.**

This is the open-source cryptographic library powering [voider](https://voider.app) — private file sharing that's encrypted, ephemeral, and open source.

## What's Included

- **CRYSTALS-Kyber (ML-KEM-768)** — NIST FIPS 203 standardized post-quantum key exchange
- **AES-256-GCM** — symmetric encryption via Web Crypto API
- **Streaming encryption** — process 15GB files with <10MB memory footprint
- **Zero-knowledge architecture** — keys never touch the server

## How It Works

Keys generated client-side (Web Crypto API)
Files encrypted in browser before upload
Key stored in URL fragment (never sent to server)
Metadata (filenames, MIME types) encrypted alongside content
Server stores only ciphertext — cannot decrypt

## Why Post-Quantum?

Adversaries harvest encrypted data today to decrypt when quantum computers arrive ("store now, decrypt later"). voider protects against this with CRYSTALS-Kyber, which has undergone nearly a decade of public cryptanalysis and is now NIST standardized.

## Architecture

| Layer | Algorithm | Purpose |
|-------|-----------|---------|
| Key Exchange | CRYSTALS-Kyber (ML-KEM-768) | Quantum-resistant key encapsulation |
| Symmetric Encryption | AES-256-GCM | File and metadata encryption |
| Key Derivation | HKDF-SHA256 | Derive encryption keys from shared secret |
| Hashing | SHA-256 | Privacy-preserving rate limiting |

## Security Properties

- **Zero-knowledge**: Server never sees plaintext or encryption keys
- **Forward secrecy**: Each transfer uses unique keys
- **Quantum resistance**: Protected against future quantum attacks
- **Ephemeral by design**: Files auto-delete in 1-24 hours

## Documentation

- [Full Cryptographic Specification](https://voider.app/crypto)
- [Security Architecture](https://voider.app/security)
- [Why Zero-Knowledge?](https://voider.app/why)

## License

MIT — use it, fork it, build on it. privacy should be accessible to everyone.

## Contributing

Contributions welcome. Please open an issue first to discuss what you would like to change.

If you find a security vulnerability, please report it privately to security@voider.dev.

---

∅ voider / private by default.
