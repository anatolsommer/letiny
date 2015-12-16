# letiny-core

A framework for building letsencrypt clients, forked from `letiny`.

Supports all of:

  * node with `ursa` (works fast)
  * node with `forge` (works on windows)
  * browser WebCrypto (not implemented, but... Let's Encrypt over WebRTC anyone?)
  * any javascript implementation

### These aren't the droids you're looking for

This is a library / framework for building letsencrypt clients.
You probably want one of these pre-built clients instead:

  * [`letsencrypt`](https://github.com/Daplie/node-letsencrypt) (compatible with the official client)
  * `letiny` (lightweight client cli)
  * `letsencrypt-express` (automatic https for express)

## Install & Usage:

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

## API

The Goodies

```javascript
// Accounts
LeCore.registerNewAccount(options, cb)        // returns (err, acmeUrls={newReg,newAuthz,newCert,revokeCert})

    { newRegUrl: '<url>'                      //    no defaults, specify acmeUrls.newAuthz
    , email: '<email>'                        //    valid email (server checks MX records)
    , accountPrivateKeyPem: '<ASCII PEM>'     //    callback to allow user interaction for tosUrl
    , agreeToTerms: fn (tosUrl, cb) {}        //    must specify agree=tosUrl to continue (or falsey to end)
    }

// Registration
LeCore.getCertificate(options, cb)            // returns (err, pems={ key, cert, ca })

    { newAuthzUrl: '<url>'                    //    specify acmeUrls.newAuthz
    , newCertUrl: '<url>'                     //    specify acmeUrls.newCert

    , domainPrivateKeyPem: '<ASCII PEM>'
    , accountPrivateKeyPem: '<ASCII PEM>'
    , domains: ['example.com']

    , setChallenge: fn (hostname, key, val, cb)
    , removeChallenge: fn (hostname, key, cb)
    }
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
LeCore.knownEndpoints                     // new-authz, new-cert, new-reg, revoke-cert


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

## Example

Below you'll find a stripped-down example. You can see the full example in the example folder.

* [example/](https://github.com/Daplie/letiny-core/blob/master/example/)

#### Register Account & Domain

This is how you **register an ACME account** and **get an HTTPS certificate**

**But wait**, there's more!
See [example/letsencrypt.js](https://github.com/Daplie/letiny-core/blob/master/example/letsencrypt.js)

```javascript
'use strict';

var LeCore = require('letiny-core');

var email = 'user@example.com';                   // CHANGE TO YOUR EMAIL
var domains = 'example.com';                      // CHANGE TO YOUR DOMAIN
var acmeDiscoveryUrl = LeCore.stagingServerUrl;   // CHANGE to production, when ready

var accountPrivateKeyPem = null;
var domainPrivateKeyPem = null;
var acmeUrls = null;

LeCore.leCrypto.generateRsaKeypair(2048, 65537, function (err, pems) {
    // ...
    LeCore.getAcmeUrls(acmeDiscoveryUrl, function (err, urls) {
        // ...
        runDemo();
    });
});

function runDemo() {
    LeCore.registerNewAccount(
        { newRegUrl: acmeUrls.newReg
        , email: email
        , accountPrivateKeyPem: accountPrivateKeyPem
        , agreeToTerms: function (tosUrl, done) {

              // agree to the exact version of these terms
              done(null, tosUrl);
          }
        }
      , function (err, regr) {

            LeCore.getCertificate(
                { newAuthzUrl: acmeUrls.newAuthz
                , newCertUrl: acmeUrls.newCert

                , domainPrivateKeyPem: domainPrivateKeyPem
                , accountPrivateKeyPem: accountPrivateKeyPem
                , domains: domains

                , setChallenge: challengeStore.set
                , removeChallenge: challengeStore.remove
                }
              , function (err, certs) {

                  // Note: you should save certs to disk (or db)
                  certStore.set(domains[0], certs, function () {

                      // ...

                  });

                }
            );
        }
    );
}
```

#### Run a Server on 80, 443, and 5001 (https/tls)

That will fail unless you have a webserver running on 80 and 443 (or 5001)
to respond to `/.well-known/acme-challenge/xxxxxxxx` with the proper token

**But wait**, there's more!
See [example/serve.js](https://github.com/Daplie/letiny-core/blob/master/example/serve.js)

```javascript
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
// Server
//
https.createServer(httpsOptions, acmeResponder).listen(5001, function () {
  console.log('Listening https on', this.address());
});
http.createServer(acmeResponder).listen(80, function () {
  console.log('Listening http on', this.address());
});
```

#### Put some storage in place

Finally, you need an implementation of `challengeStore`:

**But wait**, there's more!
See

* [example/challenge-store.js](https://github.com/Daplie/letiny-core/blob/master/challenge-store.js)
* [example/cert-store.js](https://github.com/Daplie/letiny-core/blob/master/cert-store.js)

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

var certCache = {};
var certStore = {
  set: function (hostname, certs, cb) {
    certCache[hostname] = certs;
    cb(null);
  }
, get: function (hostname, cb) {
    cb(null, certCache[hostname]);
  }
, remove: function (hostname, cb) {
    delete certCache[hostname];
    cb(null);
  }
};
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
