const DecryptionService = require('./decryptionService');

async function testDecryption() {
    try {
        // You'll replace this with an actual encrypted sample from your frontend
        const encryptedSample = "eyJpdiI6WzEwMyw0OCw0NywyMjMsMTIwLDQyLDg5LDc1LDEzNiw4MSwyMTMsNl0sInNhbHQiOlsxMDMsMjM4LDE0MiwxMDUsNDUsMjM5LDE3NywxNzMsMjM0LDE3Niw1OSwxMDgsNzgsNzIsMTIwLDE5OF0sImNpcGhlcnRleHQiOlsxMTUsODgsMzgsOTIsMTYyLDE0Myw1NSw5MywxMzcsMTk5LDYwLDEwMSwxMDQsMTE1LDgyLDkzLDEwMSwxNjYsMjM2LDksNjIsMTIzLDEwLDU0LDE3NCwxODksMTE3LDIyMSwxMjgsMjMwLDQ0LDIsMTEsMTEyLDIyNSwyMDAsMTk3LDMwLDExMSwxNDQsMTgxLDc1LDE1OCwxNjEsMjQ1LDQ5LDE2Myw5LDIwMCw2OCwxLDE0MiwyNDAsMSwyNTEsMjM2LDE5MCwxMjgsMTQwLDYwLDEzNCwyNDAsODksMjQ4LDE3OCwxMDRdfQ==";

        const decryptionService = new DecryptionService();
        const decrypted = await decryptionService.decrypt(encryptedSample);

        console.log('Successfully decrypted data:');
        console.log(JSON.stringify(decrypted, null, 2));
    } catch (error) {
        console.error('Test failed:', error.message);
    }
}

testDecryption();