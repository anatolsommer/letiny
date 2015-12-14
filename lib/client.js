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


function getCert(options, cb) {
  var state={
    validatedDomains:[],
    validAuthorizationURLs:[]
  };

  options.newReg=options.newReg || 'https://acme-v01.api.letsencrypt.org/acme/new-reg';

  if (!options.email) {
    return cb(new Error('No "email" option specified!'));
  }
  if (typeof options.domains==='string') {
    state.domains=options.domains.split(/[, ]+/);
  } else if (options.domains && options.domains instanceof Array) {
    state.domains=options.domains.slice();
  } else {
    return cb(new Error('No valid "domains" option specified!'));
  }

  if ((_DEBUG=options.debug)) {
    if (!''.green) {
      require('colors');
    }
    log=console.log.bind(console);
  } else {
    log=NOOP;
  }

  if (options.fork && !~process.argv.indexOf('--letiny-fork')) {
    state.child=child.fork(__filename, ['--letiny-fork']);
    if (options.challenge) {
      return cb(new Error('fork+challenge not supported yet'));
    }
    state.child.send({request:options});
    state.child.on('message', function(msg) {
      var res;
      if (msg.result) {
        res=msg.result;
        cb(res.err ? new Error(res.err) : null, res.cert, res.key, res.ca);
      }
    });
    return;
  }

  if (options.accountKey) {
    if (options.accountKey.length>255) {
      state.accountKeyPEM=options.accountKey;
    } else {
      try {
        state.accountKeyPEM=fs.readFileSync(options.accountKey);
      } catch(err) {
        if (err.code==='ENOENT') {
          makeAccountKeyPair(true);
        } else {
          return handleErr(err, 'Failed to load accountKey');
        }
      }
      try {
        state.accountKeyPair=cryptoUtil.importPemPrivateKey(state.accountKeyPEM);
      } catch(err) {
        return handleErr(err, 'Failed to parse accountKey');
      }
      initAcme();
    }
  } else {
    makeAccountKeyPair();
  }

  function makeAccountKeyPair(save) {
    var keypair;
    log('Generating account keypair...');
    keypair=pki.rsa.generateKeyPair(2048);
    state.accountKeyPEM=pki.privateKeyToPem(keypair.privateKey);
    state.accountKeyPair=cryptoUtil.importPemPrivateKey(state.accountKeyPEM);
    if (save) {
      try {
        fs.writeFileSync(options.accountKey, state.accountKeyPEM);
      } catch(err) {
        return handleErr(err, 'Failed to save accountKey');
      }
    }
    initAcme();
  }

  function initAcme() {
    state.acme=new Acme(state.accountKeyPair);
    makeKeyPair();
  }

  function makeKeyPair() {
    var keypair;
    if (options.privateKey) {
      state.certPrivateKeyPEM=options.privateKey;
    } else {
      log('Generating cert keypair...');
      keypair=pki.rsa.generateKeyPair(2048);
      state.certPrivateKeyPEM=pki.privateKeyToPem(keypair.privateKey);
    }
    try {
      state.certPrivateKey=cryptoUtil.importPemPrivateKey(state.certPrivateKeyPEM);
    } catch(err) {
      return handleErr(err, 'Failed to parse privateKey');
    }
    register();
  }

  function register() {
    post(options.newReg, {
      resource:'new-reg',
      contact:['mailto:'+options.email]
    }, getTerms);
  }

  function getTerms(err, res) {
    var links;

    if (err || Math.floor(res.statusCode/100)!==2) {
      return handleErr(err, 'Registration request failed');
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
      log(state.termsURL);
      request.get(state.termsURL, getAgreement);
    } else {
      getChallenges();
    }
  }

  function getAgreement(err, res, body) {
    if (err) {
      return handleErr(err, 'Couldn\'t get agreement');
    }
    log('The CA requires your agreement to terms:\n'+state.termsURL);
    sendAgreement();
  }

  function sendAgreement() {
    if (state.termsRequired && !options.agreeTerms) {
      return handleErr(null, 'The CA requires your agreement to terms: '+state.termsURL);
    }

    log('Posting agreement to: '+state.registrationURL);

    post(state.registrationURL, {
      resource:'reg',
      agreement:state.termsURL
    }, function(err, res, body) {
      if (err || Math.floor(res.statusCode/100)!==2) {
        return handleErr(err, 'Couldn\'t POST agreement back to server', body);
      } else {
        nextDomain();
      }
    });
  }

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

    post(state.newAuthorizationURL, {
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

    if (options.webroot) {
      try {
        mkdirp(path.dirname(options.webroot+'/'+challengePath));
        fs.writeFileSync(path.normalize(options.webroot+'/'+challengePath), keyAuthorization);
        challengeDone();
      } catch(err) {
        handleErr(err, 'Could not write challange file to disk');
      }
    } else if (typeof options.challenge==='function') {
      options.challenge(state.domain, '/'+challengePath, keyAuthorization, challengeDone);
    } else {
      return handleErr(null, 'No "challenge" function or "webroot" option given.');
    }

    function challengeDone() {
      post(state.responseURL, {
        resource:'challenge',
        keyAuthorization:keyAuthorization
      }, function(err, res, body) {
        ensureValidation(err, res, body, function unlink() {
          if (options.webroot) {
            fs.unlinkSync(path.normalize(options.webroot+'/'+challengePath));
          }
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
    post(state.newCertificateURL, {
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
    var cert, pfx;
    try {
      cert=certBufferToPEM(state.certificate);
      if (options.certFile) {
        fs.writeFileSync(options.certFile, cert);
      }
      if (options.keyFile) {
        fs.writeFileSync(options.keyFile, state.certPrivateKeyPEM);
      }
      if (options.caFile) {
        fs.writeFileSync(options.caFile, state.caCert);
      }
      if (options.pfxFile) {
        try {
          pfx=forge.pkcs12.toPkcs12Asn1(
            pki.privateKeyFromPem(state.certPrivateKeyPEM),
            [pki.certificateFromPem(cert), pki.certificateFromPem(state.caCert)],
            options.pfxPassword || '',
            options.aes ? {} : {algorithm:'3des'}
          );
          pfx=new Buffer(forge.asn1.toDer(pfx).toHex(), 'hex');
        } catch(err) {
          handleErr(err, 'Could not convert to PKCS#12');
        }
        fs.writeFileSync(options.pfxFile, pfx);
      }
      cb(null, cert, state.certPrivateKeyPEM, state.caCert);
    } catch(err) {
      handleErr(err, 'Could not write output files. Please check permissions!');
    }
  }

  function post(url, body, cb) {
    return state.acme.post(url, body, cb);
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

exports.getCert=getCert;

