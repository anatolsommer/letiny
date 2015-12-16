// That will fail unless you have a webserver running on 80 and 443 (or 5001)
// to respond to `/.well-known/acme-challenge/xxxxxxxx` with the proper token
'use strict';

module.exports.init = function (deps) {
  var tls = require('tls');
  var https = require('https');
  var http = require('http');


  var LeCore = deps.LeCore;
  var httpsOptions = deps.httpsOptions;
  var challengeStore = deps.challengeStore;
  var certStore = deps.certStore;


  //
  // Challenge Handler
  //
  function acmeResponder(req, res) {
    if (0 !== req.url.indexOf(LeCore.acmeChallengePrefix)) {
      res.end('Hello World!');
      return;
    }

    var key = req.url.slice(LeCore.acmeChallengePrefix.length);

    challengeStore.get(req.hostname, key, function (err, val) {
      res.end(val || 'Error');
    });
  }


  //
  // SNI Cert Handler
  //
  function certGetter(hostname, cb) {
    certStore.get(hostname, function (err, certs) {
      if (!certs) {
        cb(null, null);
        return;
      }

      // Note: you should cache this context in memory
      // so that you aren't creating a new one every time
      var context = tls.createSecureContext({
        cert: certs.cert
      , key: certs.key
      });

      cb(null, context);
    });
  }


  //
  // Server
  //
  httpsOptions.SNICallback = certGetter;
  https.createServer(httpsOptions, acmeResponder).listen(443, function () {
    console.log('Listening https on', this.address());
  });
  https.createServer(httpsOptions, acmeResponder).listen(5001, function () {
    console.log('Listening https on', this.address());
  });
  http.createServer().listen(80, function () {
    console.log('Listening http on', this.address());
  });
};
