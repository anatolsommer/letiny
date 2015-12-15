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
