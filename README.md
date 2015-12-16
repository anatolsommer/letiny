# letiny-core

A framework for building letsencrypt clients, forked from `letiny`.

  * browser
  * node with `forge` (works on windows)
  * node with `ursa` (works fast)
  * any javascript implementation

## Usage:

```bash
npm install --save letiny-core
```

```javascript
'use strict';

var leCore = require('leCore');

leCore.
```

## API

```javascript
LeCore.registerNewAccount(options, cb);

LeCore.getCertificate(options, cb);

LeCore.Acme                               // Signs requests with JWK
  acme = new Acme(lePrivateKey)           // privateKey format is abstract
  acme.post(url, body, cb)                // POST with signature
  acme.parseLinks(link)                   // (internal) parses 'link' header
  acme.getNonce(url, cb)                  // (internal) HEAD request to get 'replay-nonce' strings

LeCore.leCrypto
  thumbprint(lePubKey)                          // generates thumbprint
  generateSignature(lePrivKey, bodyBuf, nonce)  // generates a signature
  importPemPrivateKey(privateKeyPem);           // returns abstract private key
```

For testing and development, you can also inject the dependencies you want to use:

```javascript
leCore.create({
  request: require('request')
, leCrypto: rquire('./lib/letsencrypt-forge')
});
```

## Licence

MPL 2.0

All of the code is available under the MPL-2.0.

Some of the files are original work not modified from `letiny`
and are made available under MIT as well (check file headers).
