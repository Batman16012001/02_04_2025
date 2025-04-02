// const crypto = require('crypto');
// require('dotenv').config();

// class DecryptionService {
//     constructor(secretKey = '123456abcdekq120') {
//         if (!secretKey) {
//             throw new Error('Encryption key not provided in environment variables');
//         }
//         this.secretKey = secretKey;
//     }

//     /**
//      * Derives a key using PBKDF2 with the same parameters as the frontend
//      * @param {string} password - The secret key
//      * @param {Buffer} salt - The salt
//      * @returns {Promise<Buffer>} - The derived key
//      */
//     async deriveKey(password, salt) {
//         return new Promise((resolve, reject) => {
//             crypto.pbkdf2(
//                 password,
//                 salt,
//                 100000, // Same iteration count as frontend
//                 32, // 256-bit key
//                 'sha256',
//                 (err, derivedKey) => {
//                     if (err) reject(err);
//                     else resolve(derivedKey);
//                 }
//             );
//         });
//     }

//     /**
//      * Decrypts data that was encrypted using AES-GCM with Web Crypto API
//      * @param {string} encryptedData - Base64 encoded JSON string containing iv, salt, and ciphertext
//      * @returns {Promise<object>} - Decrypted data
//      */
//     async decrypt(encryptedData) {
//         try {
//             if (!encryptedData) {
//                 throw new Error('No encrypted data provided');
//             }

//             // Parse the base64 encoded string to get the encrypted data components
//             const payload = JSON.parse(Buffer.from(encryptedData, 'base64').toString());

//             // Extract components
//             const iv = Buffer.from(new Uint8Array(payload.iv));
//             const salt = Buffer.from(new Uint8Array(payload.salt));
//             const ciphertext = Buffer.from(new Uint8Array(payload.ciphertext));

//             // Derive the key using PBKDF2 with the same parameters as frontend
//             const key = await this.deriveKey(this.secretKey, salt);

//             // Create a decipher with AES-GCM
//             const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);

//             // Decrypt the data
//             let decrypted = decipher.update(ciphertext);

//             try {
//                 decrypted = Buffer.concat([decrypted, decipher.final()]);
//             } catch (error) {
//                 console.error('Error finalizing decryption:', error.message);
//                 throw new Error('Failed to authenticate encrypted data');
//             }

//             // Parse and return the decrypted JSON data
//             const decryptedStr = decrypted.toString('utf8');
//             return JSON.parse(decryptedStr);
//         } catch (error) {
//             console.error('Decryption failed:', error.message);
//             throw new Error(`Failed to decrypt data: ${error.message}`);
//         }
//     }
// }

// module.exports = DecryptionService;


const crypto = require('crypto');
require('dotenv').config();

class DecryptionService {
    constructor(secretKey = '123456abcdekq120') {
        this.secretKey = secretKey;
    }

    async deriveKey(password, salt) {
        return new Promise((resolve, reject) => {
            crypto.pbkdf2(
                password,
                Buffer.from(salt),
                100000,
                32,
                'sha256',
                (err, derivedKey) => {
                    if (err) reject(err);
                    else resolve(derivedKey);
                }
            );
        });
    }

    async decrypt(encryptedData) {
        try {
            // Parse the base64 encoded string
            const payloadStr = Buffer.from(encryptedData, 'base64').toString();
            const payload = JSON.parse(payloadStr);

            // Extract components
            const iv = Buffer.from(payload.iv);
            const salt = Buffer.from(payload.salt);
            const ciphertext = Buffer.from(payload.ciphertext);

            // Derive the key
            const key = await this.deriveKey(this.secretKey, salt);

            // Try alternative decryption approach - treating the entire ciphertext as data + tag
            const algorithm = 'aes-256-gcm';
            const decipher = crypto.createDecipheriv(algorithm, key, iv);

            // In Web Crypto, the auth tag is part of the ciphertext
            // For node's crypto, we need to extract it (16 bytes from the end)
            const tagLength = 16;

            if (ciphertext.length <= tagLength) {
                throw new Error('Ciphertext too short');
            }

            const actualCiphertext = ciphertext.slice(0, ciphertext.length - tagLength);
            const authTag = ciphertext.slice(ciphertext.length - tagLength);

            // Set the auth tag
            decipher.setAuthTag(authTag);

            // Decrypt
            let decrypted = decipher.update(actualCiphertext);
            try {
                decrypted = Buffer.concat([decrypted, decipher.final()]);
            } catch (finalError) {
                // Try with a different approach - some implementations might not separate the auth tag
                console.log("First approach failed, trying alternative...");

                // Try treating the entire buffer as containing both data and tag
                const decipher2 = crypto.createDecipheriv(algorithm, key, iv);
                try {
                    let result = decipher2.update(ciphertext);
                    result = Buffer.concat([result, decipher2.final()]);
                    return JSON.parse(result.toString());
                } catch (finalError2) {
                    console.error("Both decryption approaches failed");
                    throw finalError2;
                }
            }

            return JSON.parse(decrypted.toString());
        } catch (error) {
            console.error("Detailed error:", error);
            throw new Error(`Failed to decrypt data: ${error.message}`);
        }
    }
}

module.exports = DecryptionService;