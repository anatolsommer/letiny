# letiny
Tiny acme client library and CLI to obtain ssl certificates (without using external commands like openssl).


## Usage:
`npm install letiny`


### Using the "webroot" option
This will create a file in `/var/www/example.com/.well-known/acme-challenge/` to verify the domain.
```js
require('letiny').getCert({
  email:'me@example.com',
  domains:['example.com', 'www.example.com'],
  webroot:'/var/www/example.com',
  certFile:'./cert.pem',
  keyFile:'./key.pem',
  caFile:'./ca.pem',
  agreeTerms:true
}, function(err, cert, key, cacert) {
  console.log(err || cert+'\n'+key+'\n'+cacert);
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
  certFile:'./cert.pem',
  keyFile:'./key.pem',
  caFile:'./ca.pem',
  agreeTerms:true
}, function(err, cert, key, cacert) {
  console.log(err || cert+'\n'+key+'\n'+cacert);
});
```

### Options
#### Required:
 * `email`: Your email adress
 * `domains`: Comma seperated string or array
 * `agreeTerms`: You need to agree the terms
 * `webroot` (string) or `challenge` (function)

#### Optional:
 * `certFile`: Path to save certificate
 * `keyFile`: Path to save private key
 * `caFile`: Path to save issuer certificate
 * `pfxFile`: Path to save PKCS#12 certificate
 * `pfxPassword`: Password for PKCS#12 certificate
 * `accountKey`: (string), path or PEM
 * `privateKey`: (string), PEM
 * `aes`: (boolean), use AES instead of 3DES for PKCS#12 certificate
 * `newReg`: URL, use *https://acme-staging.api.letsencrypt.org/acme/new-reg* for testing
 * `fork`: (boolean), fork a child process


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
-k, --key <path>         path to save your private key (privkey.pem)
-i, --ca <path>          path to save issuer certificate (cacert.pem)
-a, --account <path>     path of the account key (optional)
--pfx <path>             path to save PKCS#12 certificate (optional)
--password <password>    password for PKCS#12 certificate (optional)
--aes                    use AES instead of 3DES for PKCS#12
--agree                  agree terms of the ACME CA (required)
--newreg <URL>           optional AMCE server newReg URL
--debug                  print debug information
```
When --pfx is used without --cert, --key and --ca no .pem files will be created.

#### Examples:
```
letiny -e me@example.com -w /var/www/example.com -d example.com --agree
letiny -e me@example.com -m -d example.com -c cert.pem -k key.pem -i ca.pem --agree
letiny -e me@example.com -m -d example.com,www.example.com --agree
letiny -e me@example.com -m -d example.com --pfx cert.pfx --password secret --agree
letiny --email me@example.com --webroot ./ --domains example.com --agree
```


## Licence
MPL 2.0

