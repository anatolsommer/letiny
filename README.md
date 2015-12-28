# letiny
Tiny acme client library and CLI to obtain ssl certificates (without using external commands like openssl).


## Command line interface
```sudo npm install letiny -g```

#### Options:
```
-h, --help               output usage information
-e, --email <email>      your email address
-w, --webroot <path>     path for webroot verification
-m, --manual             use manual verification
-d, --domains <domains>  domains (comma seperated)
-c, --cert <path>        path to save your certificate (cert.pem)
-k, --key <path>         path to load or save your private key (privkey.pem)
-i, --ca <path>          path to save issuer certificate (cacert.pem)
-a, --account <path>     path to load or save account key (optional)
--pfx <path>             path to save PKCS#12 certificate (optional)
--password <password>    password for PKCS#12 certificate (optional)
--aes                    use AES instead of 3DES for PKCS#12
--agree                  agree terms of the ACME CA (required)
--url <URL>              optional AMCE server URL
--debug                  print debug information
```
When --pfx is used without --cert, --key and --ca no .pem files will be created.

#### Examples:
```
letiny -e me@example.com -w /var/www/example.com -d example.com --agree
letiny -e me@example.com -m -d example.com -a account.pem -c cert.pem -k key.pem -i ca.pem --agree
letiny -e me@example.com -m -d example.com,www.example.com --agree
letiny -e me@example.com -m -d example.com --pfx cert.pfx --password secret --agree
letiny --email me@example.com --webroot ./ --domains example.com --agree
```


## Library:
`npm install letiny`

### Using the "webroot" option
This will create a file in `/var/www/example.com/.well-known/acme-challenge/` to verify the domain.
```js
require('letiny').getCert({
  email:'me@example.com',
  domains:['example.com', 'www.example.com'],
  webroot:'/var/www/example.com',
  agreeTerms:true
}, function(err, cert, key, caCert, accountKey) {
  console.log(err || cert+'\n'+key+'\n'+caCert);
});
```

### Using the "challenge" option
This allows you to provide the challenge data on your own, so you can obtain certificates on-the-fly within your software.
```js
require('letiny').getCert({
  email:'me@example.com',
  domains:'example.com',
  challenge:function(domain, path, data, done) {
    // make http://+domain+path serving "data"
    done();
  },
  agreeTerms:true
}, function(err, cert, key, caCert, accountKey) {
  console.log(err || cert+'\n'+key+'\n'+caCert);
});
```

### Save accountKey and privateKey to files for later reuse
```js
require('letiny').getCert({
  email:'me@example.com',
  domains:'example.com,www.example.com',
  webroot:'/var/www/example.com',
  certFile:'/etc/ssl/private/example.com/cert.pem',
  caFile:'/etc/ssl/private/example.com/ca.pem',
  privateKey:'/etc/ssl/private/example.com/key.pem',
  accountKey:/etc/ssl/private/example.com/account.pem,
  agreeTerms:true
}, function(err) {
  console.log(err);
});
```


### Options
#### Required:
 * `email`: (string), Your email adress
 * `domains`: (comma seperated string or array)
 * `agreeTerms`: (boolean), You need to agree the terms
 * `webroot` (string) or `challenge` (function)

#### Optional:
 * `certFile`: (string), Path to save certificate
 * `keyFile`: (string), Path to save private key
 * `caFile`: (string), Path to save issuer certificate
 * `pfxFile`: (string), Path to save PKCS#12 certificate
 * `pfxPassword`: (string), Password for PKCS#12 certificate
 * `accountKey`: (string), PEM or path to load or save key
 * `privateKey`: (string), PEM or path to load or save key
 * `aes`: (boolean), use AES instead of 3DES for PKCS#12 certificate
 * `url`: (string), server URL, use *https://acme-staging.api.letsencrypt.org* for testing
 * `fork`: (boolean), fork a child process


### Helper
#### webrootChallengeMiddleware
Serves webroot challenge files from a directory (can differ from public directory).
```js
app.use(letiny.webrootChallengeMiddleware('/some/path'));
```
```js
app.use(letiny.webrootChallengeMiddleware()); // default: './'
```

#### getExpirationDate
Returns a javascript Date for validBefore field of a pem string.
```js
var expires=letiny.getExpirationDate(certPem);
```


## Licence
MPL 2.0

