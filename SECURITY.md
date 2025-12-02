# Security Policy

## Reporting a Vulnerability

**Do not open a public issue.** Please report security vulnerabilities privately.

**Email:** [teamvoider@protonmail.com](mailto:teamvoider@protonmail.com)

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (optional)

We will acknowledge your report within **48 hours** and provide a detailed response within **7 days**.

---

## Scope

This policy covers the cryptographic implementation in this repository:

| File | Description |
|------|-------------|
| `src/encryption.js` | Core AES-256-GCM + Kyber encryption |
| `src/streamingEncryption.js` | Chunked streaming for large files |
| `src/crypto.worker.js` | Web Worker encryption thread |

---

## Out of Scope

- Denial of service attacks
- Social engineering
- Issues in dependencies (report to [@PaulMillr](https://github.com/paulmillr/noble-post-quantum/issues) or relevant maintainers)

---

## Response Timeline

| Stage | Timeframe |
|-------|-----------|
| Acknowledgment | 48 hours |
| Initial assessment | 7 days |
| Fix development | 14-30 days (severity dependent) |
| Public disclosure | After fix is deployed |

---

## Recognition

We appreciate researchers who help keep voider secure. With your permission, we'll credit you on our [security page](https://voider.app/security).

---

## Verification

Verify this code matches what runs on [voider.app](https://voider.app):

1. Open voider.app in your browser
2. Open DevTools → Sources tab
3. Navigate to the encryption modules
4. Compare the logic with this repository

The encryption implementation is identical. No server-side modifications.
