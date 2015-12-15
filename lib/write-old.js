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
