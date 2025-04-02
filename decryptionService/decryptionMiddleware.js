const DecryptionService = require('./decryptionService');

// Initialize the decryption service
const decryptionService = new DecryptionService();

/**
 * Middleware to handle encrypted request data
 */
const decryptionMiddleware = async (req, res, next) => {
    try {
        // Check if request contains encrypted login credentials
        if (req.body && req.body.login_creds) {
            try {
                // Decrypt the login credentials
                const decryptedData = await decryptionService.decrypt(req.body.login_creds);
                console.log("Successfully decrypted data in middleware");

                // Replace the encrypted data with the decrypted data
                req.body = decryptedData;
            } catch (error) {
                console.error("Decryption middleware error:", error.message);
                // Continue anyway, let the route handler decide what to do
            }
        }

        // Process any other encrypted fields if needed
        // ...

        next();
    } catch (error) {
        console.error("Error in decryption middleware:", error.message);
        next();
    }
};

module.exports = decryptionMiddleware;