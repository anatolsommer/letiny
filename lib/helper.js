var forge=require('node-forge');

module.exports={

  getExpirationDate:function(certPem) {
    var cert=forge.pki.certificateFromPem(certPem);
    return cert.validity.notAfter;
  }

};
