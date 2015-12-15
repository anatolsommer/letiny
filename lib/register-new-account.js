/*!
 * letiny
 * Copyright(c) 2015 Anatol Sommer <anatol@anatol.at>
 * Some code used from https://github.com/letsencrypt/boulder/tree/master/test/js
 * MPL 2.0
*/

'use strict';

var NOOP=function () {}, log=NOOP;
var request=require('request');
var cryptoUtil=require('./crypto-util');
var Acme = require('./acme-client');

function registerNewAccount(options, cb) {
  var state = {};

  if (!options.accountPrivateKeyPem) {
    return handleErr(new Error("options.accountPrivateKeyPem must be an ascii private key pem"));
  }
  if (!options.agreeToTerms) {
    cb(new Error("options.agreeToTerms must be function (tosUrl, fn => (err, true))"));
    return;
  }
  if (!options.newReg) {
    cb(new Error("options.newReg must be the a new registration url"));
    return;
  }
  if (!options.email) {
    cb(new Error("options.email must be an email"));
    return;
  }

  state.accountKeyPem=options.accountPrivateKeyPem;
  state.accountKeyPair=cryptoUtil.importPemPrivateKey(state.accountKeyPem);
  state.acme=new Acme(state.accountKeyPair);

  register();

  function register() {
    state.acme.post(options.newReg, {
      resource:'new-reg',
      contact:['mailto:'+options.email]
    }, getTerms);
  }

  function getTerms(err, res) {
    var links;

    if (err || Math.floor(res.statusCode/100)!==2) {
      return handleErr(err, 'Registration request failed: ' + res.body.toString('utf8'));
    }

    links=Acme.parseLink(res.headers.link);
    if (!links || !('next' in links)) {
      return handleErr(err, 'Server didn\'t provide information to proceed (1)');
    }

    state.registrationURL=res.headers.location;
    state.newAuthorizationURL=links.next;
    state.termsRequired=('terms-of-service' in links);

    if (state.termsRequired) {
      state.termsURL=links['terms-of-service'];
      options.agreeToTerms(state.termsURL, function (err, agree) {
        if (err) {
          return handleErr(err);
        }
        if (!agree) {
          return handleErr(new Error("You must agree to the terms of use at '" + state.termsURL + "'"));
        }

        state.agreeTerms = agree;
        state.termsURL=links['terms-of-service'];
        log(state.termsURL);
        request.get(state.termsURL, getAgreement);
      });
    } else {
      cb();
    }
  }

  function getAgreement(err/*, res, body*/) {
    if (err) {
      return handleErr(err, 'Couldn\'t get agreement');
    }
    log('The CA requires your agreement to terms:\n'+state.termsURL);
    sendAgreement();
  }

  function sendAgreement() {
    if (state.termsRequired && !state.agreeTerms) {
      return handleErr(null, 'The CA requires your agreement to terms: '+state.termsURL);
    }

    log('Posting agreement to: '+state.registrationURL);

    state.acme.post(state.registrationURL, {
      resource:'reg',
      agreement:state.termsURL
    }, function(err, res, body) {
      if (err || Math.floor(res.statusCode/100)!==2) {
        return handleErr(err, 'Couldn\'t POST agreement back to server', body);
      } else {
        cb(null, body);
      }
    });
  }

  function handleErr(err, text, info) {
    log(text, err, info);
    cb(err || new Error(text));
  }
}

module.exports = registerNewAccount;
