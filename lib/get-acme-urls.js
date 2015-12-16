/*!
 * letiny-core
 * Copyright(c) 2015 AJ ONeal <aj@daplie.com> https://daplie.com
 * Apache-2.0 OR MIT (and hence also MPL 2.0)
*/
'use strict';

module.exports.create = function (deps) {
  var request = deps.request;
  var knownUrls = deps.LeCore.knownEndpoints;

  function getAcmeUrls(acmeDiscoveryUrl, cb) {

    // TODO check response header on request for cache time
    return request({
      url: acmeDiscoveryUrl
    }, function (err, resp) {
      if (err) {
        cb(err);
        return;
      }

      var data = resp.body;

      if ('string' === typeof data) {
        try {
          data = JSON.parse(data);
        } catch(e) {
          cb(e);
          return;
        }
      }

      if (4 !== Object.keys(data).length) {
        console.warn("This Let's Encrypt / ACME server has been updated with urls that this client doesn't understand");
        console.warn(data);
      }

      if (!knownUrls.every(function (url) {
        return data[url];
      })) {
        console.warn("This Let's Encrypt / ACME server is missing urls that this client may need.");
        console.warn(data);
      }

      cb(null, {
        newAuthz: data['new-authz']
      , newCert: data['new-cert']
      , newReg: data['new-reg']
      , revokeCert: data['revoke-cert']
      });
    });
  }

  return getAcmeUrls;
};
