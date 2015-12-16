/*!
 * letiny
 * Copyright(c) 2015 Anatol Sommer <anatol@anatol.at>
 * Some code used from https://github.com/letsencrypt/boulder/tree/master/test/js
 * MPL 2.0
*/

'use strict';
module.exports.create = function (deps) {
  var NOOP=function () {}, log=NOOP;
  var request=deps.request;
  var importPemPrivateKey=deps.leCrypto.importPemPrivateKey;
  var Acme = deps.Acme;

  function registerNewAccount(options, cb) {
    var state = {};

    if (!options.accountPrivateKeyPem) {
      return handleErr(new Error("options.accountPrivateKeyPem must be an ascii private key pem"));
    }
    if (!options.agreeToTerms) {
      cb(new Error("options.agreeToTerms must be function (tosUrl, fn => (err, true))"));
      return;
    }
    if (!options.newRegUrl) {
      cb(new Error("options.newRegUrl must be the a new registration url"));
      return;
    }
    if (!options.email) {
      cb(new Error("options.email must be an email"));
      return;
    }

    state.accountKeyPem=options.accountPrivateKeyPem;
    state.accountKeyPair=importPemPrivateKey(state.accountKeyPem);
    state.acme=new Acme(state.accountKeyPair);

    register();

    function register() {
      state.acme.post(options.newRegUrl, {
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

      state.registrationUrl=res.headers.location;
      // TODO should we pass this along?
      //state.newAuthorizationUrl=links.next;
      state.termsRequired=('terms-of-service' in links);

      if (state.termsRequired) {
        state.termsUrl=links['terms-of-service'];
        options.agreeToTerms(state.termsUrl, function (err, agree) {
          if (err) {
            return handleErr(err);
          }
          if (!agree) {
            return handleErr(new Error("You must agree to the terms of use at '" + state.termsUrl + "'"));
          }

          state.agreeTerms = agree;
          state.termsUrl=links['terms-of-service'];
          log(state.termsUrl);
          request.get(state.termsUrl, getAgreement);
        });
      } else {
        cb(null, null);
      }
    }

    function getAgreement(err/*, res, body*/) {
      if (err) {
        return handleErr(err, 'Couldn\'t get agreement');
      }
      log('The CA requires your agreement to terms:\n'+state.termsUrl);
      sendAgreement();
    }

    function sendAgreement() {
      if (state.termsRequired && !state.agreeTerms) {
        return handleErr(null, 'The CA requires your agreement to terms: '+state.termsUrl);
      }

      log('Posting agreement to: '+state.registrationUrl);

      state.acme.post(state.registrationUrl, {
        resource:'reg',
        agreement:state.termsUrl
      }, function(err, res, body) {
        var data;

        if (err || Math.floor(res.statusCode/100)!==2) {
          return handleErr(err, 'Couldn\'t POST agreement back to server', body);
        }

        data = body;
        // handle for node and browser
        if ('string' === typeof body) {
          try {
            data = JSON.parse(body);
          } catch(e) {
            // ignore
          }
        } else {
          // might be a buffer
          data = body.toString('utf8');
          if (!(data.length > 10)) {
            // probably json
            data = body;
          }
        }

        cb(null, data);
      });
    }

    function handleErr(err, text, info) {
      log(text, err, info);
      cb(err || new Error(text));
    }
  }

  return registerNewAccount;
};
