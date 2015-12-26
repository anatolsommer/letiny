'use strict';

var forge=require('node-forge'), util=require('./acme-util'),
  path=require('path'), fs=require('fs');

module.exports={

  getExpirationDate:function(certPem) {
    var cert=forge.pki.certificateFromPem(certPem);
    return cert.validity.notAfter;
  },

  webrootChallengeMiddleware:function(basePath) {
    var regex=/^\/\.well-known\/acme-challenge\/([\w-]{43})$/;
    basePath=path.resolve(basePath || '', '.well-known/acme-challenge')+'/';
    return function webrootChallengeMiddleware(req, res, next) {
      var match=req.path.match(regex);
      if (!match) {
        return next();
      }
      fs.readFile(basePath+match[1], function(err, data) {
        if (err) {
          next();
        } else {
          res.send(data);
        }
      });
    };
  },

  certBufferToPem: function(cert) {
    cert=util.toStandardB64(cert.toString('base64'));
    cert=cert.match(/.{1,64}/g).join('\n');
    return '-----BEGIN CERTIFICATE-----\n'+cert+'\n-----END CERTIFICATE-----';
  }

};
