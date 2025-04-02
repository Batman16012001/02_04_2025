const crypto = require("crypto");

class EncryptionService {
  constructor(secretKey = process.env.ENCRYPTION_KEY) {
    if (!secretKey) {
      console.error("Encryption key not found in environment variables");
      throw new Error("Encryption key not provided");
    }
    this.secretKey = secretKey;
  }

  async getKey(salt) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.webcrypto.subtle.importKey(
      "raw",
      enc.encode(this.secretKey),
      { name: "PBKDF2" },
      false,
      ["deriveKey"]
    );

    return crypto.webcrypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt,
        iterations: 100000,
        hash: "SHA-256",
      },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      true,
      ["decrypt"]
    );
  }

  async decrypt(encryptedData) {
    try {
      const payload = encryptedData; // Received from server

      // Convert base64 to Uint8Array
      const iv = new Uint8Array(Buffer.from(payload.iv, "base64"));
      const salt = new Uint8Array(Buffer.from(payload.salt, "base64"));
      const ciphertext = new Uint8Array(
        Buffer.from(payload.ciphertext, "base64")
      );
      const authTag = new Uint8Array(Buffer.from(payload.authTag, "base64"));

      // Derive the same key
      const key = await this.getKey(salt);

      // Append authTag to ciphertext (AES-GCM requires authTag at the end)
      const encryptedWithTag = new Uint8Array([...ciphertext, ...authTag]);

      // Decrypt the data
      const decrypted = await crypto.webcrypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        key,
        encryptedWithTag
      );

      return JSON.parse(new TextDecoder().decode(decrypted));
    } catch (error) {
      console.error("Decryption failed:", error);
      throw new Error("Failed to decrypt data");
    }
  }
}

// Example Usage
const encryptedData = {
  iv: "2xQWMIWcZ+PqPb1G",
  salt: "7OG7LaDs4nE2JQI4aY5iKQ==",
  ciphertext: "8E6IWqI1FgYkzTVWBHb+UYThy5yXfd0yBGzsZnSBtdmLRCIXjRlj3ZcajCI=",
  authTag: "6pG7+enRozlUmq8LpHBsXQ==",
};

const encryptionService = new EncryptionService("SuperSecretKey123!");
encryptionService
  .decrypt(encryptedData)
  .then((data) => console.log("Decrypted Data:", data));
