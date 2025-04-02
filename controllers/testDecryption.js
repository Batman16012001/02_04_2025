const DecryptionService = require("./decryptionService");

async function testDecryption() {
  try {
    // You'll replace this with an actual encrypted sample from your frontend
    const encryptedSample =
      "eyJpdiI6WzY5LDEzOCw2OSwyNDUsNDMsMiwxMTAsOTUsMTY2LDIzMCwyMDYsODBdLCJzYWx0IjpbNzAsMjE4LDY5LDEzOSw1NCw2LDIwOCwxMzQsMTAxLDIwOSwxMzgsMTk0LDEyMiwxNDYsMzAsMTcwXSwiY2lwaGVydGV4dCI6WzIxNyw0MSwxMTYsMjI2LDIxNCw3MiwxNjQsMjksMTgxLDE5NywxMjIsNjUsMTQ1LDYwLDE2MSwxMTksNTEsMjE1LDE1NCwyMTMsMjM4LDkzLDI0NiwxODEsMTQ2LDAsNDIsMTcwLDE2OSwyMjAsMjUzLDc4LDY1LDIwMCw2NywyMCwxNzAsMjM1LDEyNywxNjcsODcsMjQsMzUsNSwxMDYsMTc4LDg5LDIzMywyMTEsNjIsMTMwLDg2LDI0NiwzNSw5MCwxOTUsNzksMF19";

    const decryptionService = new DecryptionService();
    const decrypted = await decryptionService.decrypt(encryptedSample);

    console.log("Successfully decrypted data:");
    console.log(JSON.stringify(decrypted, null, 2));
  } catch (error) {
    console.error("Test failed:", error.message);
  }
}

testDecryption();
