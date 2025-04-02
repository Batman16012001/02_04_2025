import CryptoJS from "crypto-js";
import { useState } from "react";
import sha256 from 'crypto-js/sha256';

function Encryption(key, message) {
    let iv = 'be7e42ea4e036b4d';

    const hashkey = sha256(key);
    var resultStr;
    var length = 32;
    if (length > hashkey.toString().length) {
        resultStr = hashkey.toString();
    } else {
        resultStr = hashkey.toString().substring(0, length);
    }

    let cipher = CryptoJS.AES.encrypt(message, CryptoJS.enc.Utf8.parse(resultStr), {
        iv: CryptoJS.enc.Utf8.parse(iv),
        padding: CryptoJS.pad.Pkcs7,
        mode: CryptoJS.mode.CBC
    });

    console.log("Encrypted Message: " + cipher.toString());

    return cipher.toString();
}

function Decryption(key, encryptedMessage) {
    let iv = 'be7e42ea4e036b4d';

    const hashkey = sha256(key);
    var resultStr;
    var length = 32;
    if (length > hashkey.toString().length) {
        resultStr = hashkey.toString();
    } else {
        resultStr = hashkey.toString().substring(0, length);
    }

    let decrypted = CryptoJS.AES.decrypt(encryptedMessage, CryptoJS.enc.Utf8.parse(resultStr), {
        iv: CryptoJS.enc.Utf8.parse(iv),
        padding: CryptoJS.pad.Pkcs7,
        mode: CryptoJS.mode.CBC
    });

    // console.log("Decrypted Message: " + decrypted.toString(CryptoJS.enc.Utf8));

    return decrypted.toString(CryptoJS.enc.Utf8);
}

export { Encryption, Decryption };
