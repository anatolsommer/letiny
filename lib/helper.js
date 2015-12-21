var forge=require('node-forge'), path=require('path');

module.exports={

  getExpirationDate:function(certPem) {
    var cert=forge.pki.certificateFromPem(certPem);
    return cert.validity.notAfter;
  },

  webrootChallengeMiddleware:function(basePath) {
    var regex=/^\/\.well-known\/acme-challenge\/([\w-]{43})$/;
    basePath=path.resolve(base || '', '.well-known/acme-challenge')+'/';
    return function webrootChallengeMiddleware(req, res, next) {
      var match=req.path.match(regex);
      if (!match) {
        next();
      } else {
        fs.readFile(basePath+match[1], function(err, data) {
          if (err) {
            next();
          } else {
            res.send(data);
          }
        });
      }
    }
  }

};
