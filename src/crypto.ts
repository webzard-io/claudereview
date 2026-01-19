import { randomBytes, createCipheriv, createDecipheriv, pbkdf2Sync } from 'crypto';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // 96 bits for GCM
const KEY_LENGTH = 32; // 256 bits
const AUTH_TAG_LENGTH = 16;
const PBKDF2_ITERATIONS = 600000; // Match browser Web Crypto API

/**
 * Generate a random encryption key for public sessions
 */
export function generateKey(): string {
  const key = randomBytes(KEY_LENGTH);
  return key.toString('base64url');
}

/**
 * Generate a random salt for password-based key derivation
 */
export function generateSalt(): string {
  return randomBytes(16).toString('base64url');
}

/**
 * Derive encryption key from password using PBKDF2
 * Uses same parameters as browser Web Crypto API for compatibility
 */
export function deriveKey(password: string, salt: string): string {
  const saltBuffer = Buffer.from(salt, 'base64url');
  const key = pbkdf2Sync(password, saltBuffer, PBKDF2_ITERATIONS, KEY_LENGTH, 'sha256');
  return key.toString('base64url');
}

/**
 * Encrypt data with AES-256-GCM
 * Returns base64url encoded ciphertext and IV
 */
export function encrypt(data: string, keyBase64: string): { ciphertext: string; iv: string } {
  const key = Buffer.from(keyBase64, 'base64url');
  const iv = randomBytes(IV_LENGTH);

  const cipher = createCipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });

  const encrypted = Buffer.concat([
    cipher.update(data, 'utf8'),
    cipher.final(),
  ]);

  const authTag = cipher.getAuthTag();

  // Combine ciphertext and auth tag
  const combined = Buffer.concat([encrypted, authTag]);

  return {
    ciphertext: combined.toString('base64url'),
    iv: iv.toString('base64url'),
  };
}

/**
 * Decrypt data with AES-256-GCM
 */
export function decrypt(ciphertextBase64: string, ivBase64: string, keyBase64: string): string {
  const key = Buffer.from(keyBase64, 'base64url');
  const iv = Buffer.from(ivBase64, 'base64url');
  const combined = Buffer.from(ciphertextBase64, 'base64url');

  // Extract ciphertext and auth tag
  const ciphertext = combined.subarray(0, combined.length - AUTH_TAG_LENGTH);
  const authTag = combined.subarray(combined.length - AUTH_TAG_LENGTH);

  const decipher = createDecipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });
  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]);

  return decrypted.toString('utf8');
}

/**
 * Encrypt session data for public sharing (random key)
 */
export function encryptForPublic(data: string): {
  ciphertext: string;
  iv: string;
  key: string;
} {
  const key = generateKey();
  const { ciphertext, iv } = encrypt(data, key);
  return { ciphertext, iv, key };
}

/**
 * Encrypt session data for private sharing (password-based)
 */
export function encryptForPrivate(
  data: string,
  password: string
): {
  ciphertext: string;
  iv: string;
  salt: string;
} {
  const salt = generateSalt();
  const key = deriveKey(password, salt);
  const { ciphertext, iv } = encrypt(data, key);
  return { ciphertext, iv, salt };
}

/**
 * Decrypt session data for private sharing
 */
export function decryptPrivate(
  ciphertext: string,
  iv: string,
  salt: string,
  password: string
): string {
  const key = deriveKey(password, salt);
  return decrypt(ciphertext, iv, key);
}

// Browser-compatible versions using Web Crypto API
// These are embedded in the HTML viewer

export const BROWSER_CRYPTO_CODE = `
// Browser-side decryption using Web Crypto API
const ALGORITHM = 'AES-GCM';
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;

// PBKDF2 for password-based key derivation
// Server and browser both use PBKDF2 with same parameters for compatibility

async function deriveKeyBrowser(password, saltBase64) {
  const salt = base64UrlDecode(saltBase64);
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 600000, // High iteration count for security
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: ALGORITHM, length: 256 },
    false,
    ['decrypt']
  );
}

async function importKey(keyBase64) {
  const keyData = base64UrlDecode(keyBase64);
  return crypto.subtle.importKey(
    'raw',
    keyData,
    { name: ALGORITHM },
    false,
    ['decrypt']
  );
}

async function decryptData(ciphertextBase64, ivBase64, key) {
  const iv = base64UrlDecode(ivBase64);
  const combined = base64UrlDecode(ciphertextBase64);

  const decrypted = await crypto.subtle.decrypt(
    { name: ALGORITHM, iv: iv },
    key,
    combined
  );

  return new TextDecoder().decode(decrypted);
}

function base64UrlDecode(str) {
  // Add padding if needed
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const padding = base64.length % 4;
  if (padding) {
    base64 += '='.repeat(4 - padding);
  }
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// Main decryption function called by viewer
async function decryptSession(encryptedBlob, iv, keyOrPassword, salt, options) {
  try {
    const canUseWebCrypto = typeof crypto !== 'undefined' && crypto.subtle && window.isSecureContext;
    if (!canUseWebCrypto) {
      const sessionId = options && options.sessionId;
      const baseUrl = options && options.baseUrl
        ? options.baseUrl
        : (window.location.origin === 'null' ? '' : window.location.origin);

      if (!sessionId || !baseUrl) {
        throw new Error('Web Crypto API unavailable and server fallback is not configured.');
      }

      const response = await fetch(baseUrl + '/api/session/' + sessionId + '/decrypt', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ keyOrPassword }),
      });

      let responseData;
      try {
        responseData = await response.json();
      } catch {
        responseData = null;
      }

      if (!response.ok) {
        const errorMessage = responseData && responseData.error
          ? responseData.error
          : 'Failed to decrypt session.';
        throw new Error(errorMessage);
      }

      if (!responseData || !responseData.session) {
        throw new Error('Invalid server response.');
      }

      return responseData.session;
    }

    let key;
    if (salt) {
      // Private session - derive key from password
      key = await deriveKeyBrowser(keyOrPassword, salt);
    } else {
      // Public session - use key directly
      key = await importKey(keyOrPassword);
    }

    const decrypted = await decryptData(encryptedBlob, iv, key);
    return JSON.parse(decrypted);
  } catch (error) {
    console.error('Decryption failed:', error);
    throw new Error('Failed to decrypt session. Wrong password or corrupted data.');
  }
}
`;
