<div align="center">

# ∅ voider-protocol

**Zero-knowledge, quantum-resistant cryptography for the [voider](https://voider.app) privacy suite.**

[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![NIST FIPS 203](https://img.shields.io/badge/NIST-FIPS%20203-green.svg)](https://csrc.nist.gov/pubs/fips/203/final)
[![JavaScript](https://img.shields.io/badge/JavaScript-ES2022-f7df1e.svg)](https://developer.mozilla.org/en-US/docs/Web/JavaScript)
[![Audited](https://img.shields.io/badge/audited-6×-8b5cf6.svg)](https://paulmillr.com/noble/)

[**Documentation**](https://voider.app/docs) · [**Security**](https://voider.app/security) · [**Report Vulnerability**](mailto:teamvoider@protonmail.com)

</div>

## Overview

voider-protocol is the cryptographic engine behind voider's privacy suite. Every tool uses battle-tested, quantum-resistant encryption.

All encryption happens client-side. The server only ever sees ciphertext. Decryption keys exist solely in URL fragments and never touch our infrastructure.

> [!NOTE]
> **What this means**
> - We **cannot read** your data — mathematically, not just by policy
> - We **cannot comply** with decryption requests — we don't have the keys
> - Future quantum computers **cannot break** today's transfers


## Cryptographic Architecture

### Files & Pastes (Quantum-Resistant)

| Layer | Algorithm | Implementation | Purpose |
|:------|:----------|:---------------|:--------|
| **Key Exchange** | CRYSTALS-Kyber (ML-KEM-768) | [@noble/post-quantum](https://github.com/paulmillr/noble-post-quantum) | Quantum-resistant key encapsulation |
| **Symmetric Encryption** | AES-256-GCM | Web Crypto API | File and metadata encryption |
| **Key Derivation** | Direct import | Web Crypto API | Kyber shared secret used directly as AES-256 key |
| **Integrity** | SHA-256 | Web Crypto API | File verification, rate limiting |

### Chat (Classical)

| Layer | Algorithm | Implementation | Purpose |
|:------|:----------|:---------------|:--------|
| **Symmetric Encryption** | XChaCha20-Poly1305 | [tweetnacl](https://github.com/dchest/tweetnacl-js) | Message encryption (NaCl secretbox) |
| **Key Distribution** | Random 256-bit | Web Crypto API | Shared via URL fragment |

> [!NOTE]
> **Why two schemes?** Files use quantum-resistant crypto for long-term protection. Chat messages are ephemeral (deleted in 1-24 hours), so classical NaCl provides excellent security with lower latency.


## Credits & Acknowledgments

Created by [**Paul Miller**](https://paulmillr.com/noble/) · [@paulmillr](https://x.com/paulmillr) · [GitHub](https://github.com/paulmillr)

The noble cryptography libraries power voider's quantum-resistant encryption. Paul's work is trusted by the most security-critical applications on the web.

| Proton Mail | MetaMask | Phantom | ethers.js | viem |
|:-----------:|:--------:|:-------:|:---------:|:----:|
| Encrypted email | Crypto wallet | Solana wallet | Ethereum library | Ethereum library |


## Security Audits

noble has been professionally audited **6 times** by leading security firms:

| Date | Auditor | Scope |
|:-----|:--------|:------|
| Sep 2024 | [Cure53](https://cure53.de) | ciphers + curves |
| Sep 2023 | [Kudelski Security](https://kudelskisecurity.com) | curves |
| Feb 2023 | [Trail of Bits](https://www.trailofbits.com) | curves |
| Feb 2022 | [Cure53](https://cure53.de) | ed25519 |
| Jan 2022 | [Cure53](https://cure53.de) | hashes |
| Apr 2021 | [Cure53](https://cure53.de) | secp256k1 |

> [!NOTE]
> Audit funding provided by the Ethereum Foundation, StarkNet, and OpenSats.
> [**View full audit reports**](https://paulmillr.com/noble/)


## How It Works

**1. Your Browser**
- Generate Kyber keypair (quantum-resistant)
- Encapsulate to get shared secret
- Use shared secret directly as AES-256 key
- Encrypt file + metadata with AES-256-GCM
- Upload ciphertext only

**2. Voider Server**
- Stores: encrypted blob, size, timestamp, expiry
- Never sees: keys, filenames, file types, plaintext

**3. Shareable Link**
- `https://voider.app/d/abc123#KeyInFragmentNeverSentToServer`
- URL fragment (after `#`) stays in browser, never sent to server

> [!TIP]
> **Why URL fragments?**
> The portion of a URL after `#` is never sent to the server per [RFC 3986](https://datatracker.ietf.org/doc/html/rfc3986#section-3.5). This is a fundamental web standard, not a voider implementation detail. Your decryption key literally cannot reach our servers.


## Security Properties

| Property | Implementation |
|:---------|:---------------|
| **Zero-knowledge** | Server never sees plaintext or encryption keys |
| **Quantum resistance** | CRYSTALS-Kyber protects against "harvest now, decrypt later" attacks |
| **Forward secrecy** | Each transfer generates unique keys |
| **Streaming encryption** | Process 15GB files with <10MB memory footprint |
| **Ephemeral by design** | Files auto-delete in 1-24 hours |
| **Metadata protection** | Filenames and MIME types encrypted alongside content |


## Why Post-Quantum Now?

> [!WARNING]
> **The "Harvest Now, Decrypt Later" Threat**
>
> Nation-states and well-resourced adversaries are recording encrypted traffic today, storing it for future decryption when large-scale quantum computers become available. Files shared today using classical encryption may be readable in 10-15 years.
>
> CRYSTALS-Kyber (ML-KEM) has undergone nearly a decade of public cryptanalysis and is now [NIST FIPS 203 standardized](https://csrc.nist.gov/pubs/fips/203/final). voider protects your data against both current and future threats.


## Usage

```javascript
import { 
  generatePQCKeyPair, 
  encapsulatePQC,
  decapsulatePQC,
  encryptFileWithPQC, 
  decryptFileWithPQC 
} from './encryption.js'

// Generate quantum-resistant keypair
const { publicKey, secretKey } = await generatePQCKeyPair()

// Encrypt file
const { 
  encryptedData, 
  iv, 
  kyberPublicKey,
  kyberCipherText,
  kyberSecretKey 
} = await encryptFileWithPQC(file, onProgress)

// Decrypt file
const plaintext = await decryptFileWithPQC(
  encryptedData, 
  iv, 
  kyberCipherText, 
  kyberSecretKey
)
```

## Contributing
Contributions welcome. Please open an issue first to discuss what you would like to change.

## Security Vulnerabilities
If you discover a security vulnerability, please report it privately to security@voider.app. Do not open a public issue. Responsible disclosure is appreciated.

## License
MIT — use it, fork it, build on it. Privacy should be accessible to everyone.
