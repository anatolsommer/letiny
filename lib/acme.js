/*!
 * letiny
 * Copyright(c) 2015-2016 Anatol Sommer <anatol@anatol.at>
 * Some code used from https://github.com/letsencrypt/boulder/tree/master/test/js
 * MPL 2.0
*/
'use strict';

var request=require('request'), cryptoUtil=require('./crypto-util'),
  fromStandardB64=require('./acme-util').fromStandardB64, crypto=require('crypto');

function Acme(privateKey, debug) {
  this.privateKey=privateKey;
  this.nonces=[];
  this.debug=debug;
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
      self.log('Storing nonce: '+res.headers['replay-nonce']);
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

  self.log('Using nonce: '+this.nonces[0]);
  payload=JSON.stringify(body, null, 2);
  jws=cryptoUtil.generateSignature(
    this.privateKey, new Buffer(payload), this.nonces.shift()
  );
  signed=JSON.stringify(jws, null, 2);

  self.log('Posting to '+url);
  self.log(signed.green);
  self.log('Payload:'+payload.blue);

  return request.post({
    url:url,
    body:signed,
    encoding:null
  }, function(err, res, body) {
    var parsed;

    if (err) {
      self.log(err);
      return cb(err);
    }
    if (res) {
      self.log(('HTTP/1.1 '+res.statusCode).yellow);
    }

    Object.keys(res.headers).forEach(function(key) {
      var value, upcased;
      value=res.headers[key];
      upcased=key.charAt(0).toUpperCase()+key.slice(1);
      self.log((upcased+': '+value).yellow);
    });

    if (body && !body.toString().match(/[^\x00-\x7F]/)) {
      try {
        parsed=JSON.parse(body);
        self.log(JSON.stringify(parsed, null, 2).cyan);
      } catch(err) {
        self.log(body.toString().cyan);
      }
    }

    if ('replay-nonce' in res.headers) {
      self.log('Storing nonce: '+res.headers['replay-nonce']);
      self.nonces.push(res.headers['replay-nonce']);
    }

    cb(err, res, body);
  });
};

Acme.prototype.log=function() {
  if (!this.debug) {
    return;
  }
  if (!''.green) {
    require('colors');
  }
  console.log.apply(console, arguments);
};

Acme.dnsKey=function(key) {
  return fromStandardB64(crypto.createHash('sha256').update(key).digest('base64'));
};

module.exports=Acme;
