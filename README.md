# letiny-core

A framework for building letsencrypt clients, forked from `letiny`.

  * node with `ursa` (works fast)
  * node with `forge` (works on windows)
  * browser WebCrypto (not implemented, but on the TODO)
  * any javascript implementation

### These aren't the droids you're looking for

This is a library / framework for building letsencrypt clients.
You probably want one of these pre-built clients instead:

  * `letsencrypt` (100% compatible with the official client)
  * `letiny` (lightweight client)
  * `letsencrypt-express` (automatic https for express)

## Usage:

```bash
npm install --save letiny-core
```

You will follow these steps to obtain certificates:

* discover ACME registration urls with `getAcmeUrls`
* register a user account with `registerNewAccount`
* implement a method to agree to the terms of service as `agreeToTos`
* get certificates with `getCertificate`
* implement a method to store the challenge token as `setChallenge`
* implement a method to get the challenge token as `getChallenge`
* implement a method to remove the challenge token as `removeChallenge`

```javascript
'use strict';

var LeCore = require('letiny-core');

var accountPrivateKeyPem = '...';                     // leCrypto.generateRsaKeypair(bitLen, exp, cb)
var domainPrivateKeyPem = '...';                      // (same)
var challengeStore = { /*get, set, remove*/ };        // see below for example

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
          { domainPrivateKeyPem: domainPrivateKeyPem
          , accountPrivateKeyPem: accountPrivateKeyPem
          , setChallenge: challengeStore.set
          , removeChallenge: challengeStore.remove
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

That will fail unless you have a webserver running on 80 and 443 (or 5001)
to respond to `/.well-known/acme-challenge/xxxxxxxx` with the proper token

```javascript
var localCerts = require('localhost.daplie.com-certificates'); // needs default certificates
var http = require('http');
var httsp = require('https');

function acmeResponder(req, res) {
  if (0 !== req.url.indexOf(LeCore.acmeChallengePrefixUrl)) {
    res.end('Hello World!');
    return;
  }

  LeCore.
}

http.createServer()
```

Finally, you need an implementation of `challengeStore`:

```javascript
var challengeCache = {};
var challengeStore = {
  set: function (hostname, key, value, cb) {
    challengeCache[key] = value;
    cb(null);
  }
, get: function (hostname, key, cb) {
    cb(null, challengeCache[key]);
  }
, remove: function (hostname, key, cb) {
    delete challengeCache[key];
    cb(null);
  }
};
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
LeCore.acmeChallengePrefix                // /.well-known/acme-challenge/
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

## Authors

  * ISRG
  * Anatol Sommer  (https://github.com/anatolsommer)
  * AJ ONeal <aj@daplie.com> (https://daplie.com)

## Licence

MPL 2.0

All of the code is available under the MPL-2.0.

Some of the files are original work not modified from `letiny`
and are made available under MIT as well (check file headers).
