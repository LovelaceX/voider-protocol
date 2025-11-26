# Voider Protocol

Open-source end-to-end encryption protocol used by [Voider](https://voider.app) for secure file transfers.

## Security Guarantees

- **Client-side encryption** - All encryption happens in your browser
- **Zero-knowledge** - Server never sees filenames, file contents, or metadata
- **Post-quantum ready** - CRYSTALS-Kyber (ML-KEM-768) protects against future quantum attacks
- **Key never leaves your device** - Encryption key stays in URL fragment (`#`), never sent to server

## Algorithms Used

### File Transfers
- **Key Exchange**: CRYSTALS-Kyber (ML-KEM-768) - NIST post-quantum standard
- **Symmetric Encryption**: AES-256-GCM
- **Chunk Size**: 1MB with unique IV per chunk

## How It Works

### Upload Flow
1. Browser generates Kyber keypair
2. Encapsulation produces shared secret + ciphertext
3. Shared secret becomes AES-256-GCM key
4. File is chunked (1MB) and each chunk encrypted with unique IV
5. Metadata (filename, size, type) encrypted separately
6. Only encrypted data sent to server
7. Kyber secret key encoded in URL fragment (never sent to server)

### Download Flow
1. Recipient receives URL with secret key in fragment
2. Browser decapsulates to recover shared secret
3. Shared secret becomes AES-256-GCM key
4. Chunks downloaded and decrypted in browser
5. File reconstructed locally

## Dependencies

- `@noble/post-quantum` - CRYSTALS-Kyber implementation

## License

MIT License - See [LICENSE](LICENSE)

## Security Audits

This code is published for transparency and public auditing. If you find a vulnerability, please report it responsibly.

## About Voider

Voider is an end-to-end encrypted file sharing service. Learn more at [voider.app](https://voider.app)
