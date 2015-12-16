/*!
 * letiny-core
 * Copyright(c) 2015 AJ ONeal <aj@daplie.com> https://daplie.com
 * Apache-2.0 OR MIT (and hence also MPL 2.0)
*/
'use strict';

var crypto = require('crypto');
var forge = require('node-forge');

function binstrToB64(binstr) {
  return new Buffer(binstr, 'binary').toString('base64');
}

function b64ToBinstr(b64) {
  return new Buffer(b64, 'base64').toString('binary');
}

function toAcmePrivateKey(forgePrivkey) {
  //var forgePrivkey = forge.pki.privateKeyFromPem(privkeyPem);

  return {
    kty: "RSA"
  , n: binstrToB64(forgePrivkey.n)
  , e: binstrToB64(forgePrivkey.e)
  , d: binstrToB64(forgePrivkey.d)
  , p: binstrToB64(forgePrivkey.p)
  , q: binstrToB64(forgePrivkey.q)
  , dp: binstrToB64(forgePrivkey.dP)
  , dq: binstrToB64(forgePrivkey.dQ)
  , qi: binstrToB64(forgePrivkey.qInv)
  };
}

function toForgePrivateKey(forgePrivkey) {
  return forge.pki.rsa.setPrivateKey(
    b64ToBinstr(forgePrivkey.n)
  , b64ToBinstr(forgePrivkey.e)
  , b64ToBinstr(forgePrivkey.d)
  , b64ToBinstr(forgePrivkey.p)
  , b64ToBinstr(forgePrivkey.q)
  , b64ToBinstr(forgePrivkey.dp)
  , b64ToBinstr(forgePrivkey.dq)
  , b64ToBinstr(forgePrivkey.qi)
  );
}

// WARNING: with forge this takes 20+ minutes on a Raspberry Pi!!!
// It takes SEVERAL seconds even on a nice macbook pro
function generateRsaKeypair(bitlen, exp, cb) {
  var pki = forge.pki;
  var keypair = pki.rsa.generateKeyPair({ bits: bitlen, e: exp });
  var pems = {
    publicKeyPem: pki.publicKeyToPem(keypair.publicKey)     // ascii PEM: ----BEGIN...
  , privateKeyPem: pki.privateKeyToPem(keypair.privateKey)  // ascii PEM: ----BEGIN...
  };

  // I would have chosen sha1 or sha2... but whatever
  pems.publicKeyMd5 = crypto.createHash('md5').update(pems.publicKeyPem).digest('hex');
  // json { n: ..., e: ..., iq: ..., etc }
  pems.privateKeyJwk = toAcmePrivateKey(keypair.privateKey);
  // deprecate
  pems.privateKeyJson = pems.privateKeyJwk;

  // TODO thumbprint

  cb(null, pems);
}

function parseAccountPrivateKey(pkj, cb) {
  var pki = forge.pki;

  Object.keys(pkj).forEach(function (key) {
    pkj[key] = new Buffer(pkj[key], 'base64');
  });

  var priv;
  var pubPem;

  try {
    priv = toForgePrivateKey(
      pkj.n // modulus
    , pkj.e // exponent
    , pkj.p
    , pkj.q
    , pkj.dp
    , pkj.dq
    , pkj.qi
    , pkj.d
    );
  } catch(e) {
    cb(e);
    return;
  }

  pubPem = pki.publicKeyToPem(priv.publicKey);
  cb(null, {
    publicKeyPem: pubPem                                  // ascii PEM: ----BEGIN...
  , privateKeyPem: pki.privateKeyToPem(priv.privateKey)   // ascii PEM: ----BEGIN...
    // json { n: ..., e: ..., iq: ..., etc }
  , privateKeyJwt: pkj
    // deprecate
  , privateKeyJson: pkj
    // I would have chosen sha1 or sha2... but whatever
  , publicKeyMd5: crypto.createHash('md5').update(pubPem).digest('hex')
  });
}

module.exports.generateRsaKeypair = generateRsaKeypair;
module.exports.privateJwkToPems = parseAccountPrivateKey;
module.exports.privatePemToJwk = toAcmePrivateKey;

// TODO deprecate
module.exports.toAcmePrivateKey = toAcmePrivateKey;
module.exports.parseAccountPrivateKey = parseAccountPrivateKey;
