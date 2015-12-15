/*!
 * letsencrypt-core
 * Copyright(c) 2015 AJ ONeal <aj@daplie.com> https://daplie.com
 * Apache-2.0 OR MIT (and hence also MPL 2.0)
*/
'use strict';

function create(deps) {
  var LeCore = {};

  LeCore.leCrypto = deps.leCrypto;
  LeCore.Acme = require('./lib/acme-client').create(deps);
  LeCore.registerNewAccount = require('./lib/register-new-account').create(deps);
  LeCore.getCertificate = require('./lib/get-certificate').create(deps);

  return LeCore;
}

module.exports = create(require('./lib/node'));
module.exports.create = create;
