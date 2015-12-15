/*!
 * letiny
 * Copyright(c) 2015 Anatol Sommer <anatol@anatol.at>
 * Some code used from https://github.com/letsencrypt/boulder/tree/master/test/js
 * MPL 2.0
*/

'use strict';

var NOOP=function () {}, log=NOOP;
var request=require('request');
var util=require('./acme-util');
var cryptoUtil=require('./crypto-util');
var Acme = require('./acme-client');

function getCert(options, cb) {
  var state={
    validatedDomains:[]
  , validAuthorizationUrls:[]
  , newAuthorizationUrl: options.newAuthorizationUrl || options.newAuthz
  , newCertificateUrl: options.newCertificateUrl || options.newCert
  };

  if (!options.accountPrivateKeyPem) {
    return handleErr(new Error("options.accountPrivateKeyPem must be an ascii private key pem"));
  }
  if (!options.domainPrivateKeyPem) {
    return handleErr(new Error("options.domainPrivateKeyPem must be an ascii private key pem"));
  }
  if (!options.setChallenge) {
    return handleErr(new Error("options.setChallenge must be function(hostname, challengeKey, tokenValue, done) {}"));
  }
  if (!options.removeChallenge) {
    return handleErr(new Error("options.removeChallenge must be function(hostname, challengeKey, done) {}"));
  }
  if (!(options.domains && options.domains.length)) {
    return handleErr(new Error("options.domains must be an array of domains such as ['example.com', 'www.example.com']"));
  }

  state.domains = options.domains.slice(0); // copy array
  try {
    state.accountKeyPem=options.accountPrivateKeyPem;
    state.accountKeyPair=cryptoUtil.importPemPrivateKey(state.accountKeyPem);
    state.acme=new Acme(state.accountKeyPair);
    state.certPrivateKeyPem=options.domainPrivateKeyPem;
    state.certPrivateKey=cryptoUtil.importPemPrivateKey(state.certPrivateKeyPem);
  } catch(err) {
    return handleErr(err, 'Failed to parse privateKey');
  }

  nextDomain();

  function nextDomain() {
    if (state.domains.length > 0) {
      getChallenges(state.domains.shift());
      return;
    } else {
      getCertificate();
    }
  }

  function getChallenges(domain) {
    state.domain=domain;

    state.acme.post(state.newAuthorizationUrl, {
      resource:'new-authz',
      identifier:{
        type:'dns',
        value:state.domain,
      }
    }, getReadyToValidate);
  }

  function getReadyToValidate(err, res, body) {
    var links, authz, httpChallenges, challenge, thumbprint, keyAuthorization, challengePath;

    if (err) {
      return handleErr(err);
    }

    if (Math.floor(res.statusCode/100)!==2) {
      return handleErr(null, 'Authorization request failed ('+res.statusCode+')');
    }

    links=Acme.parseLink(res.headers.link);
    if (!links || !('next' in links)) {
      return handleErr(err, 'Server didn\'t provide information to proceed (2)');
    }

    state.authorizationUrl=res.headers.location;
    state.newCertificateUrl=links.next;

    authz=JSON.parse(body);

    httpChallenges=authz.challenges.filter(function(x) {
      return x.type==='http-01';
    });
    if (httpChallenges.length===0) {
      return handleErr(null, 'Server didn\'t offer any challenge we can handle.');
    }
    challenge=httpChallenges[0];

    thumbprint=cryptoUtil.thumbprint(state.accountKeyPair.publicKey);
    keyAuthorization=challenge.token+'.'+thumbprint;
    challengePath='.well-known/acme-challenge/'+challenge.token;
    state.responseUrl=challenge.uri;
    state.path=challengePath;

    options.setChallenge(state.domain, '/'+challengePath, keyAuthorization, challengeDone);

    function challengeDone() {
      state.acme.post(state.responseUrl, {
        resource:'challenge',
        keyAuthorization:keyAuthorization
      }, function(err, res, body) {
        ensureValidation(err, res, body, function unlink() {
          options.removeChallenge(state.domain, '/'+challengePath, function () {
            // ignore
          });
        });
      });
    }
  }

  function ensureValidation(err, res, body, unlink) {
    var authz;

    if (err || Math.floor(res.statusCode/100)!==2) {
      unlink();
      return handleErr(err, 'Authorization status request failed ('+res.statusCode+')');
    }

    authz=JSON.parse(body);

    if (authz.status==='pending') {
      setTimeout(function() {
        request.get(state.authorizationUrl, {}, function(err, res, body) {
          ensureValidation(err, res, body, unlink);
        });
      }, 1000);
    } else if (authz.status==='valid') {
      log('Validating domain ... done');
      state.validatedDomains.push(state.domain);
      state.validAuthorizationUrls.push(state.authorizationUrl);
      unlink();
      nextDomain();
    } else if (authz.status==='invalid') {
      unlink();
      return handleErr(null, 'The CA was unable to validate the file you provisioned', body);
    } else {
      unlink();
      return handleErr(null, 'CA returned an authorization in an unexpected state', authz);
    }
  }

  function getCertificate() {
    var csr=cryptoUtil.generateCSR(state.certPrivateKey, state.validatedDomains);
    log('Requesting certificate...');
    state.acme.post(state.newCertificateUrl, {
      resource:'new-cert',
      csr:csr,
      authorizations:state.validAuthorizationUrls
    }, downloadCertificate);
  }

  function downloadCertificate(err, res, body) {
    var links, certUrl;

    if (err || Math.floor(res.statusCode/100)!==2) {
      log('Certificate request failed with error ', err);
      if (body) {
        log(body.toString());
      }
      return handleErr(err, 'Certificate request failed');
    }

    links=Acme.parseLink(res.headers.link);
    if (!links || !('up' in links)) {
      return handleErr(err, 'Failed to fetch issuer certificate');
    }

    log('Requesting certificate: done');

    state.certificate=body;
    certUrl=res.headers.location;
    request.get({
      url:certUrl,
      encoding:null
    }, function(err, res, body) {
      if (err) {
        return handleErr(err, 'Failed to fetch cert from '+certUrl);
      }
      if (res.statusCode!==200) {
        return handleErr(err, 'Failed to fetch cert from '+certUrl, res.body.toString());
      }
      if (body.toString()!==state.certificate.toString()) {
        handleErr(null, 'Cert at '+certUrl+' did not match returned cert');
      } else {
        log('Successfully verified cert at '+certUrl);
        log('Requesting issuer certificate...');
        request.get({
          url:links.up,
          encoding:null
        }, function(err, res, body) {
          if (err || res.statusCode!==200) {
            return handleErr(err, 'Failed to fetch issuer certificate');
          }
          state.caCert=certBufferToPem(body);
          log('Requesting issuer certificate: done');
          done();
        });
      }
    });
  }

  function done() {
    var cert;

    try {
      cert=certBufferToPem(state.certificate);
    } catch(e) {
      console.error(e.stack);
      //cb(new Error("Could not write output files. Please check permissions!"));
      handleErr(e, 'Could not write output files. Please check permissions!');
      return;
    }

    cb(null, {
      cert: cert
    , key: state.certPrivateKeyPem
    , ca: state.caCert
    });
  }

  function handleErr(err, text, info) {
    log(text, err, info);
    cb(err || new Error(text));
  }

}

function certBufferToPem(cert) {
  cert=util.toStandardB64(cert.toString('base64'));
  cert=cert.match(/.{1,64}/g).join('\n');
  return '-----BEGIN CERTIFICATE-----\n'+cert+'\n-----END CERTIFICATE-----';
}

module.exports = getCert;
