'use strict';

//var LeCore = require('letiny-core');
var LeCore = require('../');

var email = process.argv[2] || 'user@example.com';    // CHANGE TO YOUR EMAIL
var domains = [process.argv[3] || 'example.com'];     // CHANGE TO YOUR DOMAIN
var acmeDiscoveryUrl = LeCore.stagingServerUrl;

var challengeStore = require('./challenge-store');
var certStore = require('./cert-store');
var serve = require('./serve');

var accountPrivateKeyPem = null;
var domainPrivateKeyPem = null;
var acmeUrls = null;


console.log('Using server', acmeDiscoveryUrl);
console.log('Creating account for', email, 'and registering certificates for', domains, 'to that account');
init();


function init() {
    getPrivateKeys(function () {

        LeCore.getAcmeUrls(acmeDiscoveryUrl, function (urls) {
        // in production choose LeCore.productionServerUrl

            acmeUrls = urls;
            runDemo();

        });
    });
}

function getPrivateKeys() {
    LeCore.leCrypto.generateRsaKeypair(2048, 65537, function (err, pems) {

        accountPrivateKeyPem = pems.privateKeyPem;
        LeCore.leCrypto.generateRsaKeypair(2048, 65537, function (err, pems) {

            domainPrivateKeyPem = pems.privateKeyPem;

        });
    });
}

function runDemo() {
    LeCore.registerNewAccount(
        { newRegUrl: acmeUrls.newReg
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
                  certStore.set(domains[0], certs, function () {

                    console.log('[certs]');
                    console.log(certs);

                  });
                  
                }
            );
        }
    );
}

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
