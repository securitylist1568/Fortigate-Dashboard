import crypto from 'crypto';

export interface EncryptedVaultPayload {
  encrypted: true;
  algorithm: 'AES-256-GCM';
  iv: string;          // Base64 encoded 12-byte IV
  ciphertext: string;  // Base64 encoded ciphertext + 16-byte authTag (Web Crypto compatible)
  generatedAt: string;
}

/**
 * Derives a 256-bit (32-byte) AES key from a passkey string using SHA-256,
 * 100% compatible with Web Crypto API `window.crypto.subtle.digest('SHA-256', ...)`.
 */
export function deriveVaultKey(passkey: string): Buffer {
  return crypto.createHash('sha256').update(passkey.trim(), 'utf8').digest();
}

/**
 * Encrypts a JSON-serializable object on the server using AES-256-GCM.
 * Appends the 16-byte GCM authentication tag to the end of the ciphertext buffer
 * so that browser `window.crypto.subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, buf)`
 * can decrypt it directly without exposing any plaintext in the network response.
 */
export function encryptSnapshotPayload(
  payload: unknown,
  passkey: string
): EncryptedVaultPayload {
  const key = deriveVaultKey(passkey);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv, {
    authTagLength: 16,
  });

  const plaintext = Buffer.from(JSON.stringify(payload), 'utf8');
  const encryptedPart = cipher.update(plaintext);
  const finalPart = cipher.final();
  const authTag = cipher.getAuthTag(); // 16 bytes (128 bits)

  // Web Crypto API expects ciphertext || authTag concatenated
  const combined = Buffer.concat([encryptedPart, finalPart, authTag]);

  return {
    encrypted: true,
    algorithm: 'AES-256-GCM',
    iv: iv.toString('base64'),
    ciphertext: combined.toString('base64'),
    generatedAt: new Date().toISOString(),
  };
}

/**
 * Node.js helper to decrypt an EncryptedVaultPayload (used in unit tests to verify round-trip).
 */
export function decryptSnapshotPayloadNode<T = unknown>(
  encObj: EncryptedVaultPayload,
  passkey: string
): T {
  const key = deriveVaultKey(passkey);
  const iv = Buffer.from(encObj.iv, 'base64');
  const combined = Buffer.from(encObj.ciphertext, 'base64');

  if (combined.length < 16) {
    throw new Error('DECRYPTION_FAILED: Ciphertext too short');
  }

  const ciphertext = combined.subarray(0, combined.length - 16);
  const authTag = combined.subarray(combined.length - 16);

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv, {
    authTagLength: 16,
  });
  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]);

  return JSON.parse(decrypted.toString('utf8')) as T;
}
