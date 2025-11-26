# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in the Voider Protocol, please report it responsibly.

**Email:** security@voider.app

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fixes (optional)

We will acknowledge your report within 48 hours and work with you on responsible disclosure.

## Scope

This policy covers the encryption implementation in this repository:
- `src/encryption.js` - Core encryption functions
- `src/streamingEncryption.js` - Chunked streaming encryption
- `src/crypto.worker.js` - Web Worker encryption

## Out of Scope

- Denial of service attacks
- Social engineering
- Issues in third-party dependencies (report to their maintainers)

## Recognition

We appreciate security researchers who help keep Voider secure. With your permission, we will acknowledge your contribution on our website.

## Verification

You can verify this code matches what runs on [voider.app](https://voider.app):
1. Open voider.app in your browser
2. Open DevTools (F12) → Sources tab
3. Navigate to the encryption modules
4. Compare the logic with this repository
