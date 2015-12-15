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
