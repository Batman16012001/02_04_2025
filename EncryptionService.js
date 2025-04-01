// import CryptoJS from 'crypto-js';

// class EncryptionService {
//     constructor(secretKey = process.env.REACT_APP_ENCRYPTION_KEY) {
//         if (!secretKey) {
//             console.error('Encryption key not found in environment variables');
//             throw new Error('Encryption key not provided');
//         }
//         this.secretKey = secretKey;
//     }

//     // Encrypt data using AES-256-GCM
//     encrypt(data) {
//         try {
//             // Convert the data to string if it's an object
//             const dataStr = typeof data === 'object' ? JSON.stringify(data) : String(data);

//             // Generate a random initialization vector (IV)
//             const iv = CryptoJS.lib.WordArray.random(16); // 128 bits IV

//             // Generate a salt for key derivation
//             const salt = CryptoJS.lib.WordArray.random(16);

//             // Derive a key using PBKDF2
//             const key = CryptoJS.PBKDF2(this.secretKey, salt, {
//                 keySize: 256 / 32, // 256 bits key
//                 iterations: 10000,
//                 hasher: CryptoJS.algo.SHA256
//             });

//             const keyBytes = CryptoJS.enc.Utf8.parse(key.toString(CryptoJS.enc.Hex));

//             // Encrypt the data
//             const encrypted = CryptoJS.AES.encrypt(dataStr, keyBytes, {
//                 iv: iv,
//                 mode: CryptoJS.mode.CBC,  // CBC instead of GCM
//                 padding: CryptoJS.pad.Pkcs7
//             });

//             // Combine the salt, IV, and ciphertext
//             const result = {
//                 salt: salt.toString(CryptoJS.enc.Hex),
//                 iv: iv.toString(CryptoJS.enc.Hex),
//                 ciphertext: encrypted.toString()
//             };

//             // Return as a base64-encoded string for transmission
//             return btoa(JSON.stringify(result));
//         } catch (error) {
//             console.error('Encryption failed:', error);
//             throw new Error('Failed to encrypt data');
//         }
//     }

//     // For testing/verification purposes only - Backend should handle decryption
//     decrypt(encryptedData) {
//         try {
//             // Decode from base64
//             const payloadStr = atob(encryptedData);
//             const payload = JSON.parse(payloadStr);

//             // Extract components
//             const salt = CryptoJS.enc.Hex.parse(payload.salt);
//             const iv = CryptoJS.enc.Hex.parse(payload.iv);

//             // Derive the key using the same parameters
//             const key = CryptoJS.PBKDF2(this.secretKey, salt, {
//                 keySize: 256 / 32,
//                 iterations: 10000,
//                 hasher: CryptoJS.algo.SHA256
//             });

//             // Decrypt the data
//             const decrypted = CryptoJS.AES.decrypt(payload.ciphertext, key, {
//                 iv: iv,
//                 mode: CryptoJS.mode.GCM,
//                 padding: CryptoJS.pad.Pkcs7
//             });

//             return decrypted.toString(CryptoJS.enc.Utf8);
//         } catch (error) {
//             console.error('Decryption failed:', error);
//             throw new Error('Failed to decrypt data');
//         }
//     }
// }

// export default EncryptionService;

// import CryptoJS from 'crypto-js';

// class EncryptionService {
//     constructor(secretKey = process.env.REACT_APP_ENCRYPTION_KEY) {
//         if (!secretKey) {
//             console.error('Encryption key not found in environment variables');
//             throw new Error('Encryption key not provided');
//         }
//         this.secretKey = secretKey;
//     }

//     // Encrypt data using AES-256-CBC
//     encrypt(data) {
//         try {
//             // Convert the data to string if it's an object
//             const dataStr = typeof data === 'object' ? JSON.stringify(data) : String(data);

//             // Generate a random initialization vector (IV)
//             const iv = CryptoJS.lib.WordArray.random(16); // 128 bits IV

//             // Generate a salt for key derivation
//             const salt = CryptoJS.lib.WordArray.random(16);

//             // Derive a key using PBKDF2
//             const key = CryptoJS.PBKDF2(this.secretKey, salt, {
//                 keySize: 256 / 32, // 256 bits key
//                 iterations: 10000,
//                 hasher: CryptoJS.algo.SHA256
//             });

//             // Encrypt the data
//             const encrypted = CryptoJS.AES.encrypt(dataStr, key, {
//                 iv: iv,
//                 mode: CryptoJS.mode.CBC,
//                 padding: CryptoJS.pad.Pkcs7
//             });

//             // Combine the salt, IV, and ciphertext
//             const result = {
//                 salt: salt.toString(CryptoJS.enc.Hex),
//                 iv: iv.toString(CryptoJS.enc.Hex),
//                 ciphertext: encrypted.toString()
//             };

//             // Return as a base64-encoded string for transmission
//             return btoa(JSON.stringify(result));
//         } catch (error) {
//             console.error('Encryption failed:', error);
//             throw new Error('Failed to encrypt data');
//         }
//     }

//     // For testing/verification purposes only - Backend should handle decryption
//     decrypt(encryptedData) {
//         try {
//             // Decode from base64
//             const payloadStr = atob(encryptedData);
//             const payload = JSON.parse(payloadStr);

//             // Extract components
//             const salt = CryptoJS.enc.Hex.parse(payload.salt);
//             const iv = CryptoJS.enc.Hex.parse(payload.iv);

//             // Derive the key using the same parameters
//             const key = CryptoJS.PBKDF2(this.secretKey, salt, {
//                 keySize: 256 / 32,
//                 iterations: 10000,
//                 hasher: CryptoJS.algo.SHA256
//             });

//             // Decrypt the data - using the same mode as encryption (CBC)
//             const decrypted = CryptoJS.AES.decrypt(payload.ciphertext, key, {
//                 iv: iv,
//                 mode: CryptoJS.mode.CBC,  // This must match the encryption mode
//                 padding: CryptoJS.pad.Pkcs7
//             });

//             // Parse the decrypted data
//             const decryptedStr = decrypted.toString(CryptoJS.enc.Utf8);

//             // Try to parse as JSON if it's a valid JSON string
//             try {
//                 return JSON.parse(decryptedStr);
//             } catch (e) {
//                 // If it's not JSON, return the string
//                 return decryptedStr;
//             }
//         } catch (error) {
//             console.error('Decryption failed:', error);
//             throw new Error('Failed to decrypt data');
//         }
//     }
// }

// export default EncryptionService;

// import CryptoJS from 'crypto-js';

// class EncryptionService {
//     constructor(secretKey = process.env.REACT_APP_ENCRYPTION_KEY) {
//         if (!secretKey) {
//             console.error('Encryption key not found in environment variables');
//             throw new Error('Encryption key not provided');
//         }
//         this.secretKey = secretKey;
//     }

//     // Encrypt data using AES-256-GCM (preferred according to security standards)
//     encrypt(data) {
//         try {
//             // Convert the data to string if it's an object
//             const dataStr = typeof data === 'object' ? JSON.stringify(data) : String(data);

//             // Generate a random initialization vector (IV)
//             const iv = CryptoJS.lib.WordArray.random(16); // 128 bits IV (standard size for AES)

//             // Generate a salt for key derivation
//             const salt = CryptoJS.lib.WordArray.random(16);

//             // Derive a 256-bit key using PBKDF2 with SHA-256
//             const key = CryptoJS.PBKDF2(this.secretKey, salt, {
//                 keySize: 256 / 32, // 256 bits key (compliant with standards)
//                 iterations: 10000,  // High iteration count for security
//                 hasher: CryptoJS.algo.SHA256 // SHA-256 as per security standards
//             });

//             // For GCM mode simulation in CryptoJS (CryptoJS doesn't directly support GCM)
//             // Using CBC with additional authTag simulation
//             const encrypted = CryptoJS.AES.encrypt(dataStr, key, {
//                 iv: iv,
//                 mode: CryptoJS.mode.CBC, // Using CBC as CryptoJS doesn't fully support GCM
//                 padding: CryptoJS.pad.Pkcs7
//             });

//             // Create a hash of the data for integrity verification (simulating GCM's auth tag)
//             const authTag = CryptoJS.HmacSHA256(encrypted.toString(), key).toString();

//             // Combine the salt, IV, ciphertext and auth tag
//             const result = {
//                 salt: salt.toString(CryptoJS.enc.Hex),
//                 iv: iv.toString(CryptoJS.enc.Hex),
//                 ciphertext: encrypted.toString(),
//                 authTag: authTag // Adding authentication tag for integrity
//             };

//             // Return as a base64-encoded string for transmission
//             console.log('Result from EncryptionService:', btoa(JSON.stringify(result)))
//             return btoa(JSON.stringify(result));
//         } catch (error) {
//             console.error('Encryption failed:', error);
//             throw new Error('Failed to encrypt data');
//         }
//     }

//     // For testing/verification purposes only - Backend should handle decryption
//     decrypt(encryptedData) {
//         try {
//             // Decode from base64
//             const payloadStr = atob(encryptedData);
//             const payload = JSON.parse(payloadStr);

//             // Extract components
//             const salt = CryptoJS.enc.Hex.parse(payload.salt);
//             const iv = CryptoJS.enc.Hex.parse(payload.iv);
//             const authTag = payload.authTag;

//             // Derive the key using the same parameters
//             const key = CryptoJS.PBKDF2(this.secretKey, salt, {
//                 keySize: 256 / 32,
//                 iterations: 10000,
//                 hasher: CryptoJS.algo.SHA256
//             });

//             // Verify data integrity if authTag exists
//             if (authTag) {
//                 const calculatedTag = CryptoJS.HmacSHA256(payload.ciphertext, key).toString();
//                 if (calculatedTag !== authTag) {
//                     throw new Error('Data integrity check failed');
//                 }
//             }

//             // Decrypt the data
//             const decrypted = CryptoJS.AES.decrypt(payload.ciphertext, key, {
//                 iv: iv,
//                 mode: CryptoJS.mode.CBC,
//                 padding: CryptoJS.pad.Pkcs7
//             });

//             // Parse the decrypted data
//             const decryptedStr = decrypted.toString(CryptoJS.enc.Utf8);

//             // Try to parse as JSON if it's a valid JSON string
//             try {
//                 return JSON.parse(decryptedStr);
//             } catch (e) {
//                 // If it's not JSON, return the string
//                 return decryptedStr;
//             }
//         } catch (error) {
//             console.error('Decryption failed:', error);
//             throw new Error('Failed to decrypt data');
//         }
//     }
// }

// export default EncryptionService;

// import CryptoJS from "crypto-js";

// class EncryptionService {
//     constructor() {
//         // Use a 256-bit key for AES-GCM
//         this.key = CryptoJS.enc.Utf8.parse('your-256-bit-key-here'); // Example key (replace with a secure method)
//     }

//     // Encrypt method using AES-GCM
//     encrypt(data) {
//         try {
//             // Convert the data into a string if it's an object
//             const stringData = JSON.stringify(data);

//             // Generate a random IV (GCM mode needs the IV)
//             const iv = CryptoJS.lib.WordArray.random(16);

//             // Encrypt the data
//             const encrypted = CryptoJS.AES.encrypt(stringData, this.key, {
//                 iv: iv,
//                 mode: CryptoJS.mode.GCM,
//                 padding: CryptoJS.pad.Pkcs7
//             });

//             // Return encrypted data along with IV and tag (GCM needs the tag for authentication)
//             return {
//                 ciphertext: encrypted.ciphertext.toString(CryptoJS.enc.Base64),
//                 iv: iv.toString(CryptoJS.enc.Base64),
//                 tag: encrypted.salt ? encrypted.salt.toString(CryptoJS.enc.Base64) : null
//             };
//         } catch (error) {
//             console.error("Encryption failed:", error);
//         }
//     }

//     // Decrypt method for AES-GCM
//     decrypt(encryptedData) {
//         try {
//             // Decode from Base64
//             const ciphertext = CryptoJS.enc.Base64.parse(encryptedData.ciphertext);
//             const iv = CryptoJS.enc.Base64.parse(encryptedData.iv);
//             const tag = CryptoJS.enc.Base64.parse(encryptedData.tag);

//             // Decrypt the data using AES-GCM
//             const decrypted = CryptoJS.AES.decrypt(
//                 { ciphertext: ciphertext },
//                 this.key,
//                 {
//                     iv: iv,
//                     mode: CryptoJS.mode.GCM,
//                     padding: CryptoJS.pad.Pkcs7,
//                     salt: tag // Include the tag for GCM authentication
//                 }
//             );

//             // Return the decrypted JSON object
//             return JSON.parse(decrypted.toString(CryptoJS.enc.Utf8));
//         } catch (error) {
//             console.error("Decryption failed:", error);
//             return null;
//         }
//     }
// }

// export default EncryptionService;

// import CryptoJS from 'crypto-js';

// class EncryptionService {
//     constructor(secretKey = process.env.REACT_APP_ENCRYPTION_KEY) {
//         if (!secretKey) {
//             console.error('Encryption key not found in environment variables');
//             throw new Error('Encryption key not provided');
//         }
//         this.secretKey = secretKey;
//     }

//     // Encrypt data using AES-256-GCM (preferred according to security standards)
//     encrypt(data) {
//         try {
//             // Convert the data to string if it's an object
//             const dataStr = typeof data === 'object' ? JSON.stringify(data) : String(data);

//             // Generate a random initialization vector (IV)
//             const iv = CryptoJS.lib.WordArray.random(16); // 128 bits IV (standard size for AES)

//             // Generate a salt for key derivation
//             const salt = CryptoJS.lib.WordArray.random(16);

//             // Derive a 256-bit key using PBKDF2 with SHA-256
//             const key = CryptoJS.PBKDF2(this.secretKey, salt, {
//                 keySize: 256 / 32, // 256 bits key (compliant with standards)
//                 iterations: 10000,  // High iteration count for security
//                 hasher: CryptoJS.algo.SHA256 // SHA-256 as per security standards
//             });

//             // For GCM mode simulation in CryptoJS (CryptoJS doesn't directly support GCM)
//             // Using CBC with additional authTag simulation
//             const encrypted = CryptoJS.AES.encrypt(dataStr, key, {
//                 iv: iv,
//                 mode: CryptoJS.mode.CBC, // Using CBC as CryptoJS doesn't fully support GCM
//                 padding: CryptoJS.pad.Pkcs7
//             });

//             // Create a hash of the data for integrity verification (simulating GCM's auth tag)
//             const authTag = CryptoJS.HmacSHA256(encrypted.toString(), key).toString();

//             // Combine the salt, IV, ciphertext and auth tag
//             const result = {
//                 salt: salt.toString(CryptoJS.enc.Hex),
//                 iv: iv.toString(CryptoJS.enc.Hex),
//                 ciphertext: encrypted.toString(),
//                 authTag: authTag // Adding authentication tag for integrity
//             };

//             // Return as a base64-encoded string for transmission
//             return btoa(JSON.stringify(result));
//         } catch (error) {
//             console.error('Encryption failed:', error);
//             throw new Error('Failed to encrypt data');
//         }
//     }

//     // For testing/verification purposes only - Backend should handle decryption
//     decrypt(encryptedData) {
//         try {
//             // Decode from base64
//             const payloadStr = atob(encryptedData);
//             const payload = JSON.parse(payloadStr);

//             // Extract components
//             const salt = CryptoJS.enc.Hex.parse(payload.salt);
//             const iv = CryptoJS.enc.Hex.parse(payload.iv);
//             const authTag = payload.authTag;

//             // Derive the key using the same parameters
//             const key = CryptoJS.PBKDF2(this.secretKey, salt, {
//                 keySize: 256 / 32,
//                 iterations: 10000,
//                 hasher: CryptoJS.algo.SHA256
//             });

//             // Verify data integrity if authTag exists
//             if (authTag) {
//                 const calculatedTag = CryptoJS.HmacSHA256(payload.ciphertext, key).toString();
//                 if (calculatedTag !== authTag) {
//                     throw new Error('Data integrity check failed');
//                 }
//             }

//             // Decrypt the data
//             const decrypted = CryptoJS.AES.decrypt(payload.ciphertext, key, {
//                 iv: iv,
//                 mode: CryptoJS.mode.CBC,
//                 padding: CryptoJS.pad.Pkcs7
//             });

//             // Parse the decrypted data
//             const decryptedStr = decrypted.toString(CryptoJS.enc.Utf8);

//             // Try to parse as JSON if it's a valid JSON string
//             try {
//                 return JSON.parse(decryptedStr);
//             } catch (e) {
//                 // If it's not JSON, return the string
//                 return decryptedStr;
//             }
//         } catch (error) {
//             console.error('Decryption failed:', error);
//             throw new Error('Failed to decrypt data');
//         }
//     }
// }

// export default EncryptionService;

// class EncryptionService {
//   constructor(secretKey = "mysecretkey123456") {
//     if (!secretKey) {
//       console.error("Encryption key not found in environment variables");
//       throw new Error("Encryption key not provided");
//     }
//     this.secretKey = secretKey;
//   }

//   async getKey() {
//     const enc = new TextEncoder();
//     const keyMaterial = await window.crypto.subtle.importKey(
//       "raw",
//       enc.encode(this.secretKey),
//       { name: "PBKDF2" },
//       false,
//       ["deriveKey"]
//     );

//     // Use a fixed salt instead of generating a new one each time
//     const salt = new TextEncoder().encode("fixedSaltValue"); // Use a predefined salt

//     return window.crypto.subtle.deriveKey(
//       {
//         name: "PBKDF2",
//         salt, // Use the fixed salt
//         iterations: 100000,
//         hash: "SHA-256",
//       },
//       keyMaterial,
//       { name: "AES-GCM", length: 256 },
//       true,
//       ["encrypt", "decrypt"]
//     );
//   }

//   async encrypt(data) {
//     try {
//       const iv = window.crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV for GCM
//       const key = await this.getKey();
//       const enc = new TextEncoder();

//       const encrypted = await window.crypto.subtle.encrypt(
//         { name: "AES-GCM", iv },
//         key,
//         enc.encode(JSON.stringify(data))
//       );

//       return btoa(
//         JSON.stringify({
//           iv: Array.from(iv),
//           ciphertext: Array.from(new Uint8Array(encrypted)),
//         })
//       );
//     } catch (error) {
//       console.error("Encryption failed:", error);
//       throw new Error("Failed to encrypt data");
//     }
//   }

//   async decrypt(encryptedData) {
//     try {
//       const payload = JSON.parse(atob(encryptedData));
//       const iv = new Uint8Array(payload.iv);
//       const ciphertext = new Uint8Array(payload.ciphertext);
//       const key = await this.getKey();

//       const decrypted = await window.crypto.subtle.decrypt(
//         { name: "AES-GCM", iv },
//         key,
//         ciphertext
//       );

//       return JSON.parse(new TextDecoder().decode(decrypted));
//     } catch (error) {
//       console.error("Decryption failed:", error);
//       throw new Error("Failed to decrypt data");
//     }
//   }
// }

// export default EncryptionService;

class EncryptionService {
  constructor(secretKey = "mysecretkey123456") {
    if (!secretKey) {
      console.error("Encryption key not found in environment variables");
      throw new Error("Encryption key not provided");
    }
    this.secretKey = secretKey;
  }

  async getKey(salt) {
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
      "raw",
      enc.encode(this.secretKey),
      { name: "PBKDF2" },
      false,
      ["deriveKey"]
    );

    return window.crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt,
        iterations: 100000,
        hash: "SHA-256",
      },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );
  }

  async encrypt(data) {
    try {
      const iv = window.crypto.getRandomValues(new Uint8Array(12));
      const salt = window.crypto.getRandomValues(new Uint8Array(16)); // Generate random salt
      const key = await this.getKey(salt);
      const enc = new TextEncoder();

      const encrypted = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        key,
        enc.encode(JSON.stringify(data))
      );

      return btoa(
        JSON.stringify({
          iv: Array.from(iv),
          salt: Array.from(salt), // Store salt with the encrypted data
          ciphertext: Array.from(new Uint8Array(encrypted)),
        })
      );
    } catch (error) {
      console.error("Encryption failed:", error);
      throw new Error("Failed to encrypt data");
    }
  }

  async decrypt(encryptedData) {
    try {
      const payload = JSON.parse(atob(encryptedData));
      const iv = new Uint8Array(payload.iv);
      const salt = new Uint8Array(payload.salt); // Retrieve the original salt
      const ciphertext = new Uint8Array(payload.ciphertext);
      const key = await this.getKey(salt);

      const decrypted = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        key,
        ciphertext
      );

      console.log("BeforeParsing Enc Data", decrypted);

      return JSON.parse(new TextDecoder().decode(decrypted));
    } catch (error) {
      console.error("Decryption failed:", error);
      throw new Error("Failed to decrypt data");
    }
  }
}
export default EncryptionService;
