#!/usr/bin/env node

var app=require('commander'), letiny=require('./client'), examples=[
  'letiny -e me@example.com -w /var/www/example.com -d example.com --agree',
  'letiny -e me@example.com -m -d example.com -c cert.pem -k key.pem -i ca.pem --agree',
  'letiny -e me@example.com -m -d example.com,www.example.com --agree',
  'letiny --email me@example.com --webroot ./ --domains example.com --agree'
];

app
  .option('-e, --email <email>', 'your email address')
  .option('-w, --webroot <path>', 'path for webroot verification OR')
  .option('-m, --manual', 'use manual verification')
  .option('-d, --domains <domains>', 'domains (comma seperated)')
  .option('-c, --cert <path>', 'path to save your certificate (cert.pem)')
  .option('-k, --key <path>', 'path to load or save your private key (privkey.pem)')
  .option('-i, --ca <path>', 'path to save issuer certificate (cacert.pem)')
  .option('-a, --account <path>', 'path to load or save account key (optional)')
  .option('--pfx <path>', 'path to save PKCS#12 certificate (optional)')
  .option('--password <password>', 'password for PKCS#12 certificate (optional)')
  .option('--aes', 'use AES instead of 3DES for PKCS#12')
  .option('--agree', 'agree terms of the ACME CA (required)')
  .option('--url <URL>', 'optional AMCE server URL')
  .option('--debug', 'print debug information')
  .on('--help', function() {
    console.log('  Examples:\n\n   '+examples.join('\n   ')+'\n');
  })
  .parse(process.argv);

if (app.rawArgs.length<=2) {
  return app.help();
} else if (!app.webroot && !app.manual) {
  return console.log('Error: You need to use "--manual" or "--webroot <path>"');
} else if (!app.domains) {
  return console.log('Error: You need to specify "--domains <domain>"');
} else if (!app.email) {
  return console.log('Error: You need to specify your "--email <address>"');
} else if (!app.agree) {
  return console.log('Error: You need to "--agree" the terms');
}

console.log('Preparing keys and requesting certificate...');

letiny.getCert({
  email:app.email,
  domains:app.domains,
  webroot:app.webroot,
  challenge:manualVerification,
  certFile:app.cert || (app.pfx ? false : 'cert.pem'),
  caFile:app.ca || (app.pfx ? false : 'cacert.pem'),
  privateKey:app.key || (app.pfx ? false : 'privkey.pem'),
  accountKey:app.account,
  pfxFile:app.pfx,
  pfxPassword:app.password,
  aes:app.aes,
  url:app.url,
  agreeTerms:app.agree,
  debug:app.debug
}, function(err, cert, key, cacert) {
  if (!err && cert && key && cacert) {
    console.log('Files successfully saved.');
    process.exit(0);
  }
  console.error('Error: ', err.stack || err || 'Something went wrong...');
  process.exit(1);
});

function manualVerification(domain, path, data, done) {
  var rl=require('readline').createInterface({
    input:process.stdin,
    output:process.stdout
  });
  console.log('\nCreate this file: http://'+domain+path);
  console.log(' containing this: '+data+'\n');
  rl.question('Press ENTER when done or Ctrl+C to exit\n', function() {
    rl.close();
    done();
  });
}
