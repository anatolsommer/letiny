'use strict';

var LeCore = require('letiny-core');

var email = process.argv[2] || 'user@example.com';    // CHANGE THIS
var domains = [process.argv[3] || 'example.com'];     // CHANGE THIS

var accountPrivateKeyPem = '...';                     // leCrypto.generateRsaKeypair(bitLen, exp, cb)
var domainPrivateKeyPem = '...';                      // (same)

var challengeStore = require('./challenge-store');
var certStore = require('cert-store');
var serve = require('./serve');

LeCore.getAcmeUrls(
  LeCore.stagingServerUrl                             // or choose LeCore.productionServerUrl
, function (err, urls) {

    LeCore.registerNewAccount(
      { newRegUrl: urls.newReg
      , email: email
      , accountPrivateKeyPem: accountPrivateKeyPem
      , agreeToTerms: function (tosUrl, done) {
          // agree to these exact terms

          console.log('[tosUrl]');
          console.log(tosUrl);
          done(null, tosUrl);
        }
      }
    , function (err, regr) {

        // Note: you should save the registration
        // record to disk (or db)
        console.log('[regr]');
        console.log(regr);

        LeCore.getCertificate(
          { domainPrivateKeyPem: domainPrivateKeyPem
          , accountPrivateKeyPem: accountPrivateKeyPem
          , setChallenge: challengeStore.set
          , removeChallenge: challengeStore.remove
          , domains: domains
          }
        , function (err, certs) {

            // Note: you should save certs to disk (or db)
            certStore
            
          }
        );

      }
    );

  }
);

//
// Setup the Server
//
serve.init({
  LeCore: LeCore
  // needs a default key and cert chain, anything will do
, httpsOptions: require('localhost.daplie.com-certificates')
, challengeStore: challengeStore
, certStore: certStore 
});
