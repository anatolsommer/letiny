/*!
 * letiny
 * Copyright(c) 2015 Anatol Sommer <anatol@anatol.at>
 * Some code used from https://github.com/letsencrypt/boulder/tree/master/test/js
 * MPL 2.0
*/

'use strict';

var _DEBUG, NOOP=new Function(), log=NOOP,
  mkdirp=require('mkdirp').sync, request=require('request'),
  forge=require('node-forge'), pki=forge.pki,
  cryptoUtil=require('./crypto-util'), util=require('./acme-util'),
  fs=require('fs'), path=require('path'), child=require('child_process');

function Acme(privateKey) {
  this.privateKey=privateKey;
  this.nonces=[];
}

Acme.prototype.getNonce=function(url, cb) {
  var self=this;

  request.head({
    url:url,
  }, function(err, res, body) {
    if (err) {
      return cb(err);
    }
    if (res && 'replay-nonce' in res.headers) {
      log('Storing nonce: '+res.headers['replay-nonce']);
      self.nonces.push(res.headers['replay-nonce']);
      cb();
      return;
    }

    cb(new Error('Failed to get nonce for request'));
  });
};

Acme.prototype.post=function(url, body, cb) {
  var self=this, payload, jws, signed;

  if (this.nonces.length===0) {
    this.getNonce(url, function(err) {
      if (err) {
        return cb(err);
      }
      self.post(url, body, cb);
    });
    return;
  }

  log('Using nonce: '+this.nonces[0]);
  payload=JSON.stringify(body, null, 2);
  jws=cryptoUtil.generateSignature(
    this.privateKey, new Buffer(payload), this.nonces.shift()
  );
  signed=JSON.stringify(jws, null, 2);

  log('Posting to '+url);
  log(signed.green);
  log('Payload:'+payload.blue);

  return request.post({
    url:url,
    body:signed,
    encoding:null
  }, function(err, res, body) {
    var parsed;

    if (err) {
      console.error(err);
      return cb(err);
    }
    if (res) {
      log(('HTTP/1.1 '+res.statusCode).yellow);
    }

    Object.keys(res.headers).forEach(function(key) {
      var value, upcased;
      value=res.headers[key];
      upcased=key.charAt(0).toUpperCase()+key.slice(1);
      log((upcased+': '+value).yellow);
    });

    if (body && !body.toString().match(/[^\x00-\x7F]/)) {
      try {
        parsed=JSON.parse(body);
        log(JSON.stringify(parsed, null, 2).cyan);
      } catch(err) {
        log(body.toString().cyan);
      }
    }

    if ('replay-nonce' in res.headers) {
      log('Storing nonce: '+res.headers['replay-nonce']);
      self.nonces.push(res.headers['replay-nonce']);
    }

    cb(err, res, body);
  });
};


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

    links=parseLink(res.headers['link']);
    if (!links || !('next' in links)) {
      return handleErr(err, 'Server didn\'t provide information to proceed (1)');
    }

    state.registrationURL=res.headers['location'];
    state.newAuthorizationURL=links['next'];
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

function getCert(options, cb) {
  var state={
    validatedDomains:[],
    validAuthorizationURLs:[]
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

    state.acme.post(state.newAuthorizationURL, {
      resource:'new-authz',
      identifier:{
        type:'dns',
        value:state.domain,
      }
    }, getReadyToValidate);
  }

  function getReadyToValidate(err, res, body) {
    var links, authz, httpChallenges, challenge, thumbprint, keyAuthorization, challengePath;

    if (err || Math.floor(res.statusCode/100)!==2) {
      return handleErr(err, 'Authorization request failed ('+res.statusCode+')');
    }

    links=parseLink(res.headers['link']);
    if (!links || !('next' in links)) {
      return handleErr(err, 'Server didn\'t provide information to proceed (2)');
    }

    state.authorizationURL=res.headers['location'];
    state.newCertificateURL=links['next'];

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
    state.responseURL=challenge['uri'];
    state.path=challengePath;

    options.setChallenge(state.domain, '/'+challengePath, keyAuthorization, challengeDone);

    function challengeDone() {
      state.acme.post(state.responseURL, {
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
        request.get(state.authorizationURL, {}, function(err, res, body) {
          ensureValidation(err, res, body, unlink);
        });
      }, 1000);
    } else if (authz.status==='valid') {
      log('Validating domain ... done');
      state.validatedDomains.push(state.domain);
      state.validAuthorizationURLs.push(state.authorizationURL);
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
    state.acme.post(state.newCertificateURL, {
      resource:'new-cert',
      csr:csr,
      authorizations:state.validAuthorizationURLs
    }, downloadCertificate);
  }

  function downloadCertificate(err, res, body) {
    var links, certURL;

    if (err || Math.floor(res.statusCode/100)!==2) {
      log('Certificate request failed with error ', err);
      if (body) {
        log(body.toString());
      }
      return handleErr(err, 'Certificate request failed');
    }

    links=parseLink(res.headers['link']);
    if (!links || !('up' in links)) {
      return handleErr(err, 'Failed to fetch issuer certificate');
    }

    log('Requesting certificate: done');

    state.certificate=body;
    certURL=res.headers['location'];
    request.get({
      url:certURL,
      encoding:null
    }, function(err, res, body) {
      if (err) {
        return handleErr(err, 'Failed to fetch cert from '+certURL);
      }
      if (res.statusCode!==200) {
        return handleErr(err, 'Failed to fetch cert from '+certURL, res.body.toString());
      }
      if (body.toString()!==state.certificate.toString()) {
        handleErr(null, 'Cert at '+certURL+' did not match returned cert');
      } else {
        log('Successfully verified cert at '+certURL);
        log('Requesting issuer certificate...');
        request.get({
          url:links['up'],
          encoding:null
        }, function(err, res, body) {
          if (err || res.statusCode!==200) {
            return handleErr(err, 'Failed to fetch issuer certificate');
          }
          state.caCert=certBufferToPEM(body);
          log('Requesting issuer certificate: done');
          done();
        });
      }
    });
  }

  function done() {
    var cert;

    try {
      cert=certBufferToPEM(state.certificate);
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

function certBufferToPEM(cert) {
  cert=util.toStandardB64(cert.toString('base64'));
  cert=cert.match(/.{1,64}/g).join('\n');
  return '-----BEGIN CERTIFICATE-----\n'+cert+'\n-----END CERTIFICATE-----';
}

function parseLink(link) {
  var links;
  try {
    links=link.split(',').map(function(link) {
      var parts, url, info;
      parts=link.trim().split(';');
      url=parts.shift().replace(/[<>]/g, '');
      info=parts.reduce(function(acc, p) {
        var m=p.trim().match(/(.+) *= *"(.+)"/);
        if (m) {
          acc[m[1]]=m[2];
        }
        return acc;
      }, {});
      info['url']=url;
      return info;
    }).reduce(function(acc, link) {
      if ('rel' in link) {
        acc[link['rel']]=link['url'];
      }
      return acc;
    }, {});
    return links;
  } catch(err) {
    return null;
  }
}

if (~process.argv.indexOf('--letiny-fork')) {
  process.on('message', function(msg) {
    if (msg.request) {
      getCert(msg.request.options, function(err, cert, key, ca) {
        process.send({
          result:{
            err:err ? err.stack : null,
            cert:cert,
            key:key,
            ca:ca
          }
        });
      });
    }
  });
}

exports.registerNewAccount=registerNewAccount;
exports.getCert=getCert;
