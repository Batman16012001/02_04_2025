var aesjs = require('aes-js');
var base64url = require('base64url');
var crypto = require("crypto")



var iv = "be7e42ea4e036b4d";



function hash(key) {
    let resultStr;
    var length = 32;
    let _key =  crypto.createHash('sha256').update(key).digest('hex');
	
    if (length > _key.toString().length) {
      resultStr = _key.toString();
    } else {
      resultStr = _key.toString().substring(0, length);
    }
    console.log("resultStr " + resultStr);
    return resultStr;
  } 


function encrypt(msg,id) {
	var key = hash(id)
    var keyBytes = aesjs.utils.utf8.toBytes(key);
    var ivBytes = aesjs.utils.utf8.toBytes(iv);

    var aesCbc = new aesjs.ModeOfOperation.cbc(keyBytes, ivBytes);
    var textBytes = aesjs.utils.utf8.toBytes(msg);
    var padded = aesjs.padding.pkcs7.pad(textBytes);
    var encryptedBytes = aesCbc.encrypt(padded);
    console.log("encrypted string "+base64url.encode(encryptedBytes));
    return base64url.encode(encryptedBytes)
}



var decrypt = ((key ,encrypted) => {
  //let key ="shubham.nalawade@acceltree.com";
  let hashkey = hash (key);
  let decipher = crypto.createDecipheriv('aes-256-cbc', hashkey, iv);
  let decrypted = decipher.update(encrypted, 'base64', 'utf8') ;
  let finalString = decrypted + decipher.final('utf8');
  console.log("decrypted Final String "+finalString );
  return finalString;
  
});



module.exports.decrypt = decrypt;
//module.exports.encrypt = encrypt('ABC','12345');
//module.exports.decrypt = decrypt("12345","RIK1Y_I0ULYGJjPjCrJbsQ");
