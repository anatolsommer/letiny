/*!
 * letiny-core
 * Copyright(c) 2015 AJ ONeal <aj@daplie.com> https://daplie.com
 * Apache-2.0 OR MIT (and hence also MPL 2.0)
*/
'use strict';

var request = require('request');
var leUtils = require('./acme-util');
var leCrypto = require('./letsencrypt-node-crypto');
var leExtra = require('./letsencrypt-forge-extra');
var leForge = require('./letsencrypt-forge');
var leUrsa;

try {
  leUrsa = require('./letsencrypt-ursa');
} catch(e) {
  leUrsa = {};
  // things will run a little slower on keygen, but it'll work on windows
  // (but don't try this on raspberry pi - 20+ MINUTES key generation)
}

// order of crypto precdence is
// * native
// * ursa
// * forge extra (the new one aimed to be less-forgey)
// * forge (fallback)
Object.keys(leUrsa).forEach(function (key) {
  if (!leCrypto[key]) {
    leCrypto[key] = leUrsa[key];
  }
});

Object.keys(leExtra).forEach(function (key) {
  if (!leCrypto[key]) {
    leCrypto[key] = leExtra[key];
  }
});

Object.keys(leForge).forEach(function (key) {
  if (!leCrypto[key]) {
    leCrypto[key] = leForge[key];
  }
});

module.exports.request = request;
module.exports.leCrypto = leCrypto;
module.exports.leUtils = leUtils;
