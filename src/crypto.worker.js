/**
 * Crypto Web Worker
 * Handles chunked encryption/decryption off the main thread
 * Uses Post-Quantum Cryptography (Kyber) + AES-256-GCM with per-chunk IVs
 *
 * QUANTUM-RESISTANT: CRYSTALS-Kyber (ML-KEM-768) for key exchange
 */

import { ml_kem768 } from '@noble/post-quantum/ml-kem.js'

const CHUNK_SIZE = 1024 * 1024 // 1MB chunks

/**
 * Message handler for worker commands
 */
self.onmessage = async (event) => {
  const { type, payload, id } = event.data

  try {
    switch (type) {
      case 'GENERATE_KEY':
        const key = await generateKey()
        const exportedKey = await exportKey(key)
        self.postMessage({ id, type: 'KEY_GENERATED', payload: { key: exportedKey } })
        break

      case 'GENERATE_PQC_KEYPAIR':
        const pqcKeyPair = generatePQCKeyPair()
        self.postMessage({ id, type: 'PQC_KEYPAIR_GENERATED', payload: pqcKeyPair })
        break

      case 'ENCAPSULATE_PQC':
        const { publicKey } = payload
        const encapsulated = encapsulatePQC(publicKey)
        self.postMessage({ id, type: 'PQC_ENCAPSULATED', payload: encapsulated })
        break

      case 'DECAPSULATE_PQC':
        const { cipherText, secretKey } = payload
        const sharedSecret = decapsulatePQC(cipherText, secretKey)
        self.postMessage({ id, type: 'PQC_DECAPSULATED', payload: { sharedSecret } })
        break

      case 'ENCRYPT_CHUNK':
        const { chunk, keyData, chunkIndex } = payload
        const encryptedChunk = await encryptChunk(chunk, keyData, chunkIndex)
        self.postMessage({ id, type: 'CHUNK_ENCRYPTED', payload: encryptedChunk }, [encryptedChunk.data.buffer])
        break

      case 'ENCRYPT_METADATA':
        const { metadata, keyData: metaKeyData } = payload
        const encryptedMetadata = await encryptMetadata(metadata, metaKeyData)
        self.postMessage({ id, type: 'METADATA_ENCRYPTED', payload: encryptedMetadata }, [encryptedMetadata.data.buffer])
        break

      case 'DECRYPT_CHUNK':
        const { encryptedData, keyData: decryptKeyData, iv } = payload
        const decryptedChunk = await decryptChunk(encryptedData, decryptKeyData, iv)
        self.postMessage({ id, type: 'CHUNK_DECRYPTED', payload: { data: decryptedChunk } }, [decryptedChunk.buffer])
        break

      case 'DECRYPT_METADATA':
        const { encryptedMetadata: encMeta, keyData: decMetaKeyData, iv: metaIv } = payload
        const decryptedMetadata = await decryptMetadata(encMeta, decMetaKeyData, metaIv)
        self.postMessage({ id, type: 'METADATA_DECRYPTED', payload: decryptedMetadata })
        break

      default:
        throw new Error(`Unknown command: ${type}`)
    }
  } catch (error) {
    self.postMessage({ id, type: 'ERROR', payload: { message: error.message } })
  }
}

/**
 * Generate a new AES-256-GCM key
 */
async function generateKey() {
  return await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  )
}

/**
 * Export key to base64 string
 */
async function exportKey(key) {
  const exported = await crypto.subtle.exportKey('raw', key)
  return arrayBufferToBase64(exported)
}

/**
 * Import key from base64 string
 */
async function importKey(keyString) {
  const keyData = base64ToArrayBuffer(keyString)
  return await crypto.subtle.importKey(
    'raw',
    keyData,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  )
}

/**
 * Encrypt a single chunk with unique IV
 * Each chunk gets its own IV for security
 */
async function encryptChunk(chunkData, keyString, chunkIndex) {
  const key = await importKey(keyString)

  // Generate unique IV for this chunk (12 bytes)
  const iv = crypto.getRandomValues(new Uint8Array(12))

  // Encrypt the chunk
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    chunkData
  )

  // Prepend IV to encrypted data
  const result = new Uint8Array(iv.length + encrypted.byteLength)
  result.set(iv, 0)
  result.set(new Uint8Array(encrypted), iv.length)

  return {
    data: result,
    chunkIndex,
    originalSize: chunkData.byteLength,
    encryptedSize: result.byteLength
  }
}

/**
 * Encrypt file metadata (filename, MIME type, size)
 * This is stored as the first "chunk" for zero-knowledge
 */
async function encryptMetadata(metadata, keyString) {
  const key = await importKey(keyString)

  // Convert metadata to JSON bytes
  const metadataBytes = new TextEncoder().encode(JSON.stringify(metadata))

  // Generate IV for metadata
  const iv = crypto.getRandomValues(new Uint8Array(12))

  // Encrypt
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    metadataBytes
  )

  // Prepend IV
  const result = new Uint8Array(iv.length + encrypted.byteLength)
  result.set(iv, 0)
  result.set(new Uint8Array(encrypted), iv.length)

  return {
    data: result,
    originalSize: metadataBytes.byteLength,
    encryptedSize: result.byteLength
  }
}

/**
 * Decrypt a chunk
 */
async function decryptChunk(encryptedData, keyString, ivData) {
  const key = await importKey(keyString)

  // If IV is embedded in data, extract it
  let iv, ciphertext
  if (ivData) {
    iv = new Uint8Array(ivData)
    ciphertext = encryptedData
  } else {
    // IV is first 12 bytes of encrypted data
    iv = new Uint8Array(encryptedData.slice(0, 12))
    ciphertext = encryptedData.slice(12)
  }

  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    ciphertext
  )

  return new Uint8Array(decrypted)
}

/**
 * Decrypt metadata
 */
async function decryptMetadata(encryptedData, keyString, ivData) {
  const decrypted = await decryptChunk(encryptedData, keyString, ivData)
  const jsonString = new TextDecoder().decode(decrypted)
  return JSON.parse(jsonString)
}

/**
 * Convert ArrayBuffer to base64 string
 */
function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer)
  let binary = ''
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i])
  }
  return btoa(binary)
}

/**
 * Convert base64 string to ArrayBuffer
 */
function base64ToArrayBuffer(base64) {
  const binary = atob(base64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes.buffer
}

/**
 * Generate Post-Quantum Cryptography keypair (CRYSTALS-Kyber)
 * @returns {{publicKey: Uint8Array, secretKey: Uint8Array}}
 */
function generatePQCKeyPair() {
  // Generate random seed for Kyber key generation
  const seed = crypto.getRandomValues(new Uint8Array(32))

  // Generate Kyber-768 keypair (NIST ML-KEM standard)
  const { publicKey, secretKey } = ml_kem768.keygen(seed)

  return { publicKey, secretKey }
}

/**
 * Encapsulate: Generate shared secret using recipient's public key
 * @param {Uint8Array} publicKey - Kyber public key
 * @returns {{sharedSecret: Uint8Array, cipherText: Uint8Array}}
 */
function encapsulatePQC(publicKey) {
  const { sharedSecret, cipherText } = ml_kem768.encapsulate(publicKey)
  return { sharedSecret, cipherText }
}

/**
 * Decapsulate: Recover shared secret using secret key and ciphertext
 * @param {Uint8Array} cipherText - Kyber ciphertext
 * @param {Uint8Array} secretKey - Kyber secret key
 * @returns {Uint8Array} - Shared secret (for AES)
 */
function decapsulatePQC(cipherText, secretKey) {
  return ml_kem768.decapsulate(cipherText, secretKey)
}
