/**
 * Streaming Encryption Module
 * Provides chunked encryption/decryption using Web Workers
 * Memory-efficient: never holds more than a few chunks in memory
 */

const CHUNK_SIZE = 1024 * 1024 // 1MB chunks
const MAX_CONCURRENT_CHUNKS = 3 // Process up to 3 chunks at a time

// Worker instance (lazy initialized)
let cryptoWorker = null
let messageId = 0
const pendingMessages = new Map()

/**
 * Initialize the crypto worker
 */
function getWorker() {
  if (!cryptoWorker) {
    cryptoWorker = new Worker(
      new URL('./crypto.worker.js', import.meta.url),
      { type: 'module' }
    )

    cryptoWorker.onmessage = (event) => {
      const { id, type, payload } = event.data
      const pending = pendingMessages.get(id)

      if (pending) {
        if (type === 'ERROR') {
          pending.reject(new Error(payload.message))
        } else {
          pending.resolve(payload)
        }
        pendingMessages.delete(id)
      }
    }

    cryptoWorker.onerror = (error) => {
      console.error('Crypto worker error:', error)
      // Reject all pending messages
      for (const [id, pending] of pendingMessages) {
        pending.reject(new Error('Worker error: ' + error.message))
        pendingMessages.delete(id)
      }
    }
  }
  return cryptoWorker
}

/**
 * Send a message to the worker and wait for response
 */
function sendWorkerMessage(type, payload, transferables = []) {
  return new Promise((resolve, reject) => {
    const id = ++messageId
    pendingMessages.set(id, { resolve, reject })
    getWorker().postMessage({ id, type, payload }, transferables)
  })
}

/**
 * Generate a new encryption key (legacy AES-only)
 * @returns {Promise<string>} Base64-encoded key
 * @deprecated Use generatePQCKey() for quantum resistance
 */
export async function generateKey() {
  const result = await sendWorkerMessage('GENERATE_KEY', {})
  return result.key
}

/**
 * Generate Post-Quantum Cryptography key material
 * Returns Kyber keypair + derived AES key as base64 string
 * @returns {Promise<{aesKeyString: string, kyberPublicKey: Uint8Array, kyberCipherText: Uint8Array, kyberSecretKey: Uint8Array}>}
 */
export async function generatePQCKey() {
  // 1. Generate Kyber keypair
  const keypairResult = await sendWorkerMessage('GENERATE_PQC_KEYPAIR', {})
  const { publicKey, secretKey } = keypairResult

  // 2. Encapsulate to get shared secret + ciphertext
  const encapsulateResult = await sendWorkerMessage('ENCAPSULATE_PQC', { publicKey })
  const { sharedSecret, cipherText } = encapsulateResult

  // 3. Convert shared secret to base64 string (for use as AES key)
  // Note: sharedSecret is Uint8Array, use it directly (not .buffer which may have wrong byteLength)
  const aesKeyString = uint8ArrayToBase64(sharedSecret)

  return {
    aesKeyString,           // Use this for encrypting chunks
    kyberPublicKey: publicKey,
    kyberCipherText: cipherText,
    kyberSecretKey: secretKey  // Goes in URL fragment
  }
}

/**
 * Helper to convert Uint8Array to URL-safe base64
 */
function uint8ArrayToBase64(bytes) {
  let binary = ''
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i])
  }
  // Return URL-safe base64 (- instead of +, _ instead of /, no padding)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
}

/**
 * Helper to convert ArrayBuffer to base64 (for backward compatibility)
 */
function arrayBufferToBase64(buffer) {
  return uint8ArrayToBase64(new Uint8Array(buffer))
}

/**
 * Calculate total number of chunks for a file
 */
export function calculateChunkCount(fileSize) {
  return Math.ceil(fileSize / CHUNK_SIZE)
}

/**
 * Read a specific chunk from a file
 * @param {File} file - The file to read from
 * @param {number} chunkIndex - Which chunk to read
 * @returns {Promise<ArrayBuffer>} - The chunk data
 */
async function readChunk(file, chunkIndex) {
  const start = chunkIndex * CHUNK_SIZE
  const end = Math.min(start + CHUNK_SIZE, file.size)
  const blob = file.slice(start, end)
  try {
    return await blob.arrayBuffer()
  } catch (err) {
    // Provide a clearer error message for file access issues
    if (err.name === 'NotFoundError') {
      throw new Error(`File "${file.name}" is no longer accessible. It may have been moved, renamed, or deleted. Please re-select the file.`)
    }
    throw err
  }
}

/**
 * Encrypt a file using streaming chunked encryption
 * Calls onChunkReady callback for each encrypted chunk
 *
 * @param {File} file - File to encrypt
 * @param {string} key - Base64-encoded encryption key
 * @param {Object} options - Options
 * @param {Function} options.onProgress - Progress callback (bytesProcessed, totalBytes)
 * @param {Function} options.onChunkReady - Called when a chunk is ready (chunkIndex, encryptedData, isLast)
 * @param {Function} options.onMetadataReady - Called when encrypted metadata is ready (encryptedData)
 * @returns {Promise<{totalChunks: number, encryptedSize: number}>}
 */
export async function encryptFileStreaming(file, key, options = {}) {
  const { onProgress, onChunkReady, onMetadataReady } = options

  const totalChunks = calculateChunkCount(file.size)
  let bytesProcessed = 0
  let totalEncryptedSize = 0

  // Step 1: Encrypt metadata (filename, MIME type, size)
  // This is the zero-knowledge part - server never sees plaintext metadata
  const metadata = {
    filename: file.name,
    mimeType: file.type || 'application/octet-stream',
    size: file.size,
    totalChunks,
    chunkSize: CHUNK_SIZE,
    version: 3 // Version 3: PQC-enabled (Kyber + AES-256-GCM)
  }

  const encryptedMetadata = await sendWorkerMessage('ENCRYPT_METADATA', {
    metadata,
    keyData: key
  })

  totalEncryptedSize += encryptedMetadata.encryptedSize

  if (onMetadataReady) {
    await onMetadataReady(encryptedMetadata.data)
  }

  // Step 2: Encrypt file chunks
  // Process chunks in batches for optimal performance
  for (let i = 0; i < totalChunks; i++) {
    // Read chunk from file
    const chunkData = await readChunk(file, i)

    // Encrypt chunk in worker
    const encryptedChunk = await sendWorkerMessage('ENCRYPT_CHUNK', {
      chunk: chunkData,
      keyData: key,
      chunkIndex: i
    }, [chunkData])

    bytesProcessed += chunkData.byteLength
    totalEncryptedSize += encryptedChunk.encryptedSize

    // Report progress
    if (onProgress) {
      onProgress(bytesProcessed, file.size)
    }

    // Deliver encrypted chunk
    if (onChunkReady) {
      const isLast = i === totalChunks - 1
      await onChunkReady(i, encryptedChunk.data, isLast)
    }
  }

  return {
    totalChunks,
    encryptedSize: totalEncryptedSize,
    metadata
  }
}

/**
 * Decrypt metadata from encrypted data
 * @param {ArrayBuffer} encryptedData - Encrypted metadata
 * @param {string} key - Base64-encoded key
 * @returns {Promise<Object>} - Decrypted metadata object
 */
export async function decryptMetadata(encryptedData, key) {
  const result = await sendWorkerMessage('DECRYPT_METADATA', {
    encryptedMetadata: encryptedData,
    keyData: key
  })
  return result
}

/**
 * Decrypt a single chunk
 * @param {ArrayBuffer} encryptedData - Encrypted chunk (with prepended IV)
 * @param {string} key - Base64-encoded key
 * @returns {Promise<Uint8Array>} - Decrypted data
 */
export async function decryptChunk(encryptedData, key) {
  const result = await sendWorkerMessage('DECRYPT_CHUNK', {
    encryptedData,
    keyData: key
  })
  return result.data
}

/**
 * Stream decrypt a file from chunks
 * @param {Function} fetchChunk - Async function(chunkIndex) that returns encrypted chunk data
 * @param {number} totalChunks - Total number of chunks
 * @param {string} key - Base64-encoded key
 * @param {Object} options - Options
 * @param {Function} options.onProgress - Progress callback (chunksDecrypted, totalChunks)
 * @param {Function} options.onChunkDecrypted - Called when chunk is decrypted (chunkIndex, data)
 * @returns {Promise<Blob>} - Decrypted file as Blob
 */
export async function decryptFileStreaming(fetchChunk, totalChunks, key, options = {}) {
  const { onProgress, onChunkDecrypted } = options

  const decryptedChunks = []

  for (let i = 0; i < totalChunks; i++) {
    // Fetch encrypted chunk
    const encryptedData = await fetchChunk(i)

    // Decrypt chunk
    const decrypted = await decryptChunk(encryptedData, key)

    decryptedChunks.push(decrypted)

    if (onProgress) {
      onProgress(i + 1, totalChunks)
    }

    if (onChunkDecrypted) {
      await onChunkDecrypted(i, decrypted)
    }
  }

  // Combine all chunks into a single Blob
  return new Blob(decryptedChunks)
}

/**
 * Clean up the worker when no longer needed
 */
export function terminateWorker() {
  if (cryptoWorker) {
    cryptoWorker.terminate()
    cryptoWorker = null
    pendingMessages.clear()
    messageId = 0
  }
}

/**
 * Export key to URL-safe base64
 * Same as before for backward compatibility
 */
export function keyToUrlSafe(key) {
  return key.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
}

/**
 * Import key from URL-safe base64
 */
export function keyFromUrlSafe(urlSafeKey) {
  let base64 = urlSafeKey.replace(/-/g, '+').replace(/_/g, '/')
  // Add padding if needed
  while (base64.length % 4) {
    base64 += '='
  }
  return base64
}

/**
 * Format bytes to human-readable size (utility function)
 */
export function formatFileSize(bytes) {
  if (bytes === 0) return '0 Bytes'
  const k = 1024
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i]
}

// Re-export chunk size for use elsewhere
export { CHUNK_SIZE }

/**
 * Encode Kyber keys for URL/storage (base64url encoding)
 */
export function encodeKyberKey(uint8Array) {
  const base64 = arrayBufferToBase64(uint8Array.buffer)
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
}

/**
 * Decode Kyber keys from URL/storage
 */
export function decodeKyberKey(base64url) {
  let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/')
  while (base64.length % 4) {
    base64 += '='
  }
  const binary = atob(base64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}
