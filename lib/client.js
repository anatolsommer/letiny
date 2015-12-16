/*!
 * letiny
 * Copyright(c) 2015 Anatol Sommer <anatol@anatol.at>
 * Some code used from https://github.com/letsencrypt/boulder/tree/master/test/js
 * MPL 2.0
*/

'use strict';

exports.Acme = require('./acme-client');
exports.registerNewAccount = require('./register-new-account');
exports.getCertificate = require('./get-certificate');
exports.getCert=function (options, cb) {
  exports.registerNewAccount(options, function () {
    exports.getCertificate(options, cb);
  });
};
