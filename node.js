/*!
 * letiny-core
 * Copyright(c) 2015 AJ ONeal <aj@daplie.com> https://daplie.com
 * Apache-2.0 OR MIT (and hence also MPL 2.0)
*/
'use strict';

function create(deps) {
  var LeCore = {};

  // Note: these are NOT DEFAULTS
  // They are de facto standards that you may
  // or may not use in your implementation
  LeCore.productionServerUrl                = "https://acme-v01.api.letsencrypt.org/directory";
  LeCore.stagingServerUrl                   = "https://acme-staging.api.letsencrypt.org/directory";
  LeCore.acmeChallengePrefix                = "/.well-known/acme-challenge/";
  LeCore.configDir                          = "/etc/letsencrypt/";
  LeCore.logsDir                            = "/var/log/letsencrypt/";
  LeCore.workDir                            = "/var/lib/letsencrypt/";
  LeCore.knownEndpoints                     = ['new-authz', 'new-cert', 'new-reg', 'revoke-cert'];

  deps.LeCore = LeCore;
  deps.Acme = LeCore.Acme = require('./lib/acme-client').create(deps);

  LeCore.getAcmeUrls = require('./lib/get-acme-urls').create(deps);
  LeCore.registerNewAccount = require('./lib/register-new-account').create(deps);
  LeCore.getCertificate = require('./lib/get-certificate').create(deps);

  LeCore.leCrypto = deps.leCrypto;

  return LeCore;
}

module.exports = create(require('./lib/node'));
module.exports.create = create;
