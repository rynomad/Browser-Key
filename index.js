require('./forge.min.js');
var keygen = {};
var pki = forge.pki;

keygen.init = function(prefix, callback, password){
  if (localStorage[prefix + '-certificate'] == undefined) {
    var self = this;
    console.log('generating keypair', forge)
    pki.rsa.generateKeyPair({bits: 2048, workers: 2}, function(er, keys){
      var cert = pki.createCertificate();
      cert.publicKey = keys.publicKey;
      cert.serialNumber = '01';
      cert.validity.notBefore = new Date();
      cert.validity.notAfter = new Date();
      cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);
      cert.sign(keys.privateKey);
      var pem = pki.certificateToPem(cert);
      var pubPem = pki.publicKeyToPem(keys.publicKey);
      var priOpenPem = pki.privateKeyToPem(keys.privateKey);
      localStorage[prefix + '-certificate'] = pem;
      localStorage[prefix + '-publicKey'] = pubPem;
      var priPem = pki.encryptRsaPrivateKey(keys.privateKey, password);
      localStorage[prefix + '-privateKey'] = priPem;
      callback(pem, priOpenPem, pubPem)
    });
  } else {
    var EncryptedPriPem = localStorage[prefix + '-privateKey']
      , priKey = pki.decryptRsaPrivateKey(EncryptedPriPem, password)
      , priPem = pki.privateKeyToPem(priKey)
      , cert = localStorage[prefix + '-certificate']
      , pubPem = localStorage[prefix + '-publicKey']
    callback(cert,  priPem, pubPem)
  }
}

module.exports = keygen.init;

