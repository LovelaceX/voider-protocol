/**
 * Voider Chat - End-to-End Encryption Utilities
 *
 * Uses X25519 for key exchange + XChaCha20-Poly1305 for symmetric encryption
 * via tweetnacl (NaCl secretbox)
 *
 * Key Flow:
 * 1. Room creator generates a random 256-bit key
 * 2. Key is stored in URL fragment (never sent to server)
 * 3. All participants derive the same key from the URL
 * 4. Messages are encrypted with the shared key before sending
 */

import nacl from 'tweetnacl'
import { encodeBase64, decodeBase64, encodeUTF8, decodeUTF8 } from 'tweetnacl-util'

/**
 * Generate a new random encryption key for a chat room
 * Returns base64-encoded key (32 bytes = 256 bits)
 */
export function generateRoomKey() {
  const key = nacl.randomBytes(nacl.secretbox.keyLength)
  return encodeBase64(key)
}

/**
 * Generate a random nonce for each message
 * Returns base64-encoded nonce (24 bytes)
 */
export function generateNonce() {
  const nonce = nacl.randomBytes(nacl.secretbox.nonceLength)
  return encodeBase64(nonce)
}

/**
 * Encrypt a message with the room key
 * @param {string} message - Plaintext message
 * @param {string} keyBase64 - Base64-encoded room key
 * @returns {{ encrypted: string, nonce: string }} Base64-encoded ciphertext and nonce
 */
export function encryptMessage(message, keyBase64) {
  const key = decodeBase64(keyBase64)
  const nonce = nacl.randomBytes(nacl.secretbox.nonceLength)
  const messageBytes = decodeUTF8(message)

  const encrypted = nacl.secretbox(messageBytes, nonce, key)

  return {
    encrypted: encodeBase64(encrypted),
    nonce: encodeBase64(nonce),
  }
}

/**
 * Decrypt a message with the room key
 * @param {string} encryptedBase64 - Base64-encoded ciphertext
 * @param {string} nonceBase64 - Base64-encoded nonce
 * @param {string} keyBase64 - Base64-encoded room key
 * @returns {string | null} Plaintext message or null if decryption fails
 */
export function decryptMessage(encryptedBase64, nonceBase64, keyBase64) {
  try {
    const key = decodeBase64(keyBase64)
    const nonce = decodeBase64(nonceBase64)
    const encrypted = decodeBase64(encryptedBase64)

    const decrypted = nacl.secretbox.open(encrypted, nonce, key)

    if (!decrypted) {
      console.error('Decryption failed - invalid key or corrupted message')
      return null
    }

    return encodeUTF8(decrypted)
  } catch (error) {
    console.error('Decryption error:', error)
    return null
  }
}

/**
 * Extract the room key from the URL fragment
 * @param {string} hash - URL hash (e.g., "#key=abc123...")
 * @returns {string | null} Room key or null if not found
 */
export function extractKeyFromHash(hash) {
  if (!hash || hash.length < 2) return null

  // Remove the # prefix
  const fragment = hash.substring(1)

  // Parse key=value format manually to avoid URLSearchParams treating + as space
  // (Base64 keys can contain + characters which get URI-encoded to %2B)
  const keyMatch = fragment.match(/^key=(.+)$/)
  if (!keyMatch) return null

  try {
    return decodeURIComponent(keyMatch[1])
  } catch {
    // If decoding fails, return the raw value
    return keyMatch[1]
  }
}

/**
 * Create URL fragment containing the room key
 * Note: Room names are NOT included in URLs for privacy - they're passed via React state
 * @param {string} key - Base64-encoded room key
 * @returns {string} URL fragment (e.g., "#key=abc123...")
 */
export function createKeyFragment(key) {
  return `#key=${encodeURIComponent(key)}`
}

/**
 * Validate a room key format
 * @param {string} keyBase64 - Base64-encoded key
 * @returns {boolean} True if valid
 */
export function isValidRoomKey(keyBase64) {
  if (!keyBase64 || typeof keyBase64 !== 'string') return false

  try {
    const key = decodeBase64(keyBase64)
    return key.length === nacl.secretbox.keyLength
  } catch {
    return false
  }
}

/**
 * Encrypt file data (for file sharing in chat)
 * @param {ArrayBuffer} data - Raw file data
 * @param {string} keyBase64 - Base64-encoded room key
 * @returns {{ encrypted: Uint8Array, nonce: string }} Encrypted data and nonce
 */
export function encryptFileData(data, keyBase64) {
  const key = decodeBase64(keyBase64)
  const nonce = nacl.randomBytes(nacl.secretbox.nonceLength)
  const dataBytes = new Uint8Array(data)

  const encrypted = nacl.secretbox(dataBytes, nonce, key)

  return {
    encrypted,
    nonce: encodeBase64(nonce),
  }
}

/**
 * Decrypt file data
 * @param {Uint8Array} encrypted - Encrypted file data
 * @param {string} nonceBase64 - Base64-encoded nonce
 * @param {string} keyBase64 - Base64-encoded room key
 * @returns {Uint8Array | null} Decrypted data or null
 */
export function decryptFileData(encrypted, nonceBase64, keyBase64) {
  try {
    const key = decodeBase64(keyBase64)
    const nonce = decodeBase64(nonceBase64)

    const decrypted = nacl.secretbox.open(encrypted, nonce, key)

    if (!decrypted) {
      console.error('File decryption failed')
      return null
    }

    return decrypted
  } catch (error) {
    console.error('File decryption error:', error)
    return null
  }
}

/**
 * Create a hash of the message content (for de-duplication)
 * @param {string} content - Message content
 * @returns {string} Base64-encoded hash
 */
export function hashMessage(content) {
  const bytes = decodeUTF8(content)
  const hash = nacl.hash(bytes)
  // Only use first 16 bytes for a shorter identifier
  return encodeBase64(hash.slice(0, 16))
}
