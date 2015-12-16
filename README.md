# letiny-core

A framework for building letsencrypt clients, forked from `letiny`.

  * node with `ursa` (works fast)
  * node with `forge` (works on windows)
  * browser WebCrypto (not implemented, but on the TODO)
  * any javascript implementation

## Usage:

```bash
npm install --save letiny-core
```

You will follow these steps to obtain certificates:

* discover ACME registration urls with `getAcmeUrls`
* register a user account with `registerNewAccount`
* implement a method to agree to the terms of service as `agreeToTos`
* get certificates with `getCertificate`

```javascript
'use strict';

var LeCore = require('letiny-core');
var accountPrivateKeyPem = '...';                     // leCrypto.generateRsaKeypair(bitLen, exp, cb)
var domainPrivateKeyPem = '...';                      // (same)

LeCore.getAcmeUrls(
  LeCore.stagingServerUrl                             // or choose LeCore.productionServerUrl
, function (err, urls) {

    LeCore.registerNewAccount(
      { newRegUrl: urls.newReg
      , email: 'user@example.com'
      , accountPrivateKeyPem: accountPrivateKeyPem
      , agreeToTerms: function (tosUrl, done) {
          // agree to these exact terms
          done(null, tosUrl);
        }
      }
    , function (err, regr) {

        // Note: you should save the registration
        // record to disk (or db)

        LeCore.getCertificate(
          {
          }
        , function (err, certs) {

            // Note: you should save certs to disk (or db)
            
          }
        )

      }
    );

  }
);
```

## API

The Goodies

```javascript
  { newRegUrl: '...'                          //    no defaults, specify LeCore.nproductionServerUrl

// Accounts 
LeCore.registerNewAccount(options, cb)        // returns (err, acmeUrls={newReg,newAuthz,newCert,revokeCert})

  { newRegUrl: '...'                          //    no defaults, specify LeCore.newAuthz
  , email: '...'                              //    valid email (server checks MX records)
  , agreeToTerms: fn (tosUrl, cb) {}          //    callback to allow user interaction for tosUrl
      // cb(err=null, agree=tosUrl)           //    must specify agree=tosUrl to continue (or falsey to end)
  }

// Registration
LeCore.getCertificate(options, cb)

  { newAuthzUrl: '...'                        //   no defaults, specify acmeUrls.newAuthz
```

Helpers & Stuff

```javascript
// Constants
LeCore.productionServerUrl                // https://acme-v01.api.letsencrypt.org/directory
LeCore.stagingServerUrl                   // https://acme-staging.api.letsencrypt.org/directory
LeCore.configDir                          // /etc/letsencrypt/
LeCore.logsDir                            // /var/log/letsencrypt/
LeCore.workDir                            // /var/lib/letsencrypt/


// HTTP Client Helpers
LeCore.Acme                               // Signs requests with JWK
  acme = new Acme(lePrivateKey)           // privateKey format is abstract
  acme.post(url, body, cb)                // POST with signature
  acme.parseLinks(link)                   // (internal) parses 'link' header
  acme.getNonce(url, cb)                  // (internal) HEAD request to get 'replay-nonce' strings

// Note: some of these are not async,
// but they will be soon. Don't rely
// on their API yet.

// Crypto Helpers
LeCore.leCrypto
  generateRsaKeypair(bitLen, exponent, cb);     // returns { privateKeyPem, privateKeyJwk, publicKeyPem, publicKeyMd5 }
  thumbprint(lePubKey)                          // generates public key thumbprint
  generateSignature(lePrivKey, bodyBuf, nonce)  // generates a signature
  privateJwkToPems(jwk)                         // { n: '...', e: '...', iq: '...', ... } to PEMs
  privatePemToJwk                               // PEM to JWK (see line above)
  importPemPrivateKey(privateKeyPem)            // (internal) returns abstract private key
```

For testing and development, you can also inject the dependencies you want to use:

```javascript
LeCore = LeCore.create({
  request: require('request')
, leCrypto: rquire('./lib/letsencrypt-forge')
});

// now uses node `request` (could also use jQuery or Angular in the browser)
LeCore.getAcmeUrls(discoveryUrl, function (err, urls) {
  console.log(urls);
});
```

## Licence

MPL 2.0

All of the code is available under the MPL-2.0.

Some of the files are original work not modified from `letiny`
and are made available under MIT as well (check file headers).
