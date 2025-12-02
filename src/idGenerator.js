/**
 * Generate short base62 IDs for file sharing URLs
 */

const BASE62_CHARS = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'

/**
 * Generate a random base62 ID
 * @param {number} length - Length of the ID (default: 8)
 * @returns {string}
 */
export function generateId(length = 8) {
  const randomBytes = new Uint8Array(length)
  crypto.getRandomValues(randomBytes)

  let id = ''
  for (let i = 0; i < length; i++) {
    // Use modulo to map random byte to base62 character
    id += BASE62_CHARS[randomBytes[i] % 62]
  }

  return id
}

/**
 * Generate a cryptographically secure base62 ID
 * Uses crypto.getRandomValues for better randomness
 * @param {number} length - Length of the ID (default: 6)
 * @returns {string}
 */
export function generateSecureId(length = 6) {
  // Generate more random bytes than needed for better distribution
  const randomBytes = new Uint8Array(length * 2)
  crypto.getRandomValues(randomBytes)

  let id = ''
  for (let i = 0; i < length; i++) {
    // Use two bytes to get a number between 0-65535, then modulo 62
    const randomValue = (randomBytes[i * 2] << 8) | randomBytes[i * 2 + 1]
    id += BASE62_CHARS[randomValue % 62]
  }

  return id
}

/**
 * Validate if a string is a valid base62 ID
 * @param {string} id
 * @returns {boolean}
 */
export function isValidId(id) {
  if (!id || typeof id !== 'string') return false

  const base62Regex = /^[0-9A-Za-z]+$/
  return base62Regex.test(id)
}
