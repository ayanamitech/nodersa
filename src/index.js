const x509 = require('@peculiar/x509');
const { Crypto } = require('@peculiar/webcrypto');
const moment = require('moment');
const randomHex = require('@ayanamitech/randomhex');

const fs = require('fs');
const path = require('path');
const process = require('process');

const { isBrowser, keysToPem, loadKeys, loadCert, loadReq, wrapFileName, getAltNameFromReq } = require('./utils');
const { signAlgo } = require('./algo');
const attrsWrapper = require('./attrs');

class NodeRSA {
  constructor(options) {
    /**
      NodeRSA parameters based off EasyRSA

      https://github.com/OpenVPN/easy-rsa/blob/master/easyrsa3/vars.example

      #set_var EASYRSA_PKI		"$PWD/pki"
    **/
    this.dir = isBrowser ? null : path.join(process.cwd(), options?.dir || 'pki');
    /**
      Define default attribute value

      #set_var EASYRSA_REQ_COUNTRY	"US"
      #set_var EASYRSA_REQ_PROVINCE	"California"
      #set_var EASYRSA_REQ_CITY	    "San Francisco"
      #set_var EASYRSA_REQ_ORG	    "Copyleft Certificate Co"
      #set_var EASYRSA_REQ_EMAIL	  "me@example.net"
      #set_var EASYRSA_REQ_OU		    "My Organizational Unit"
      #set_var EASYRSA_REQ_CN		    "ChangeMe"
    **/
    this.attrs = {
      country:  options?.req?.country  || 'US',
      province: options?.req?.province || 'California',
      city:     options?.req?.city     || 'San Francisco',
      org:      options?.req?.org      || 'Copyleft Certificate Co',
      email:    options?.req?.email    || 'me@example.net',
      ou:       options?.req?.ou       || 'My Organizational Unit',
    };
    /**
      List of supported algorithms

      https://github.com/PeculiarVentures/webcrypto#supported-algorithms

      #set_var EASYRSA_KEY_SIZE	   2048
      #set_var EASYRSA_ALGO		     rsa
      #set_var EASYRSA_CURVE		   secp384r1
      #set_var EASYRSA_DIGEST		   "sha256"
    **/
    this.algo = {
      keysize: options?.algo?.keysize || 2048,
      algo:    options?.algo?.algo    || 'rsa',
      curve:   options?.algo?.curve   || 'secp384r1',
      digest:  options?.algo?.digest  || 'sha256',
    };
    /**
      #set_var EASYRSA_CA_EXPIRE	 3650
      #set_var EASYRSA_CERT_EXPIRE 825
      #set_var EASYRSA_CRL_DAYS	   180
      #set_var EASYRSA_CERT_RENEW	 30
    **/
    this.expireCA = options?.expireCA || 7300,
    this.expireCert = options?.expireCert || 364,
    /**
      TO-DO: Add Certificate revocation list support

      https://github.com/PeculiarVentures/x509/pull/20

    this.publishCRL = 180,
    **/
    this.allowRenew = options?.allowRenew || 30;
    this.commonName = options?.commonName || 'Node-RSA CA';
    this.commonClientName = options?.commonClientName || 'Node-RSA Client';
    this.domains = options?.domains || ['localhost', 'example.net'];
    this.ips = options?.ips || [];
    this.serial = options?.serial || '01';
    this.serialBytes = options?.serialBytes || 16;
    this.rootCert = options?.rootCert || {};
    this.rootKeys = options?.rootKeys || {};
    this.reqs = options?.reqs || [];
    this.reqKeys = options?.reqKeys || [];
  }
  initPKI({force = false} = {}) {
    // Not necessary for browser environment
    if (isBrowser) {
      return;
    }
    const dirStats = fs.existsSync(this.dir);
    if (!dirStats) {
      fs.mkdirSync(path.join(this.dir));
      fs.mkdirSync(path.join(this.dir, 'private'));
      fs.mkdirSync(path.join(this.dir, 'reqs'));
      fs.mkdirSync(path.join(this.dir, 'issued'));
      fs.mkdirSync(path.join(this.dir, 'certs_by_serial'));
      return;
    }
    if (force) {
      fs.rmdirSync(this.dir, { recursive: true, force: true });
      fs.mkdirSync(path.join(this.dir));
      fs.mkdirSync(path.join(this.dir, 'private'));
      fs.mkdirSync(path.join(this.dir, 'reqs'));
      fs.mkdirSync(path.join(this.dir, 'issued'));
      fs.mkdirSync(path.join(this.dir, 'certs_by_serial'));
      return;
    }
    throw ({code: 'EEXIST'});
  }
  async buildCA({commonName = this.commonName, attributes, serialNumber = this.serial, serialNumberBytes = this.serialBytes, existingPrivateKey} = {}) {
    const crypto = new Crypto();
    const date = moment();
    x509.cryptoProvider.set(crypto);
    // Keys for CA Certificate
    const keys = await loadKeys({thisKeys: this.rootKeys, dir: this.dir, algo: this.algo, privateKey: existingPrivateKey, fileName: './private/ca.key', crypto});
    const serial = serialNumber || randomHex(serialNumberBytes);
    const cert = await x509.X509CertificateGenerator.create({
      serialNumber: serial,
      subject: attrsWrapper(attributes ? { ...attributes, cn: commonName } : { ...this.attrs, cn: commonName }),
      issuer: attrsWrapper(attributes ? { ...attributes, cn: commonName } : { ...this.attrs, cn: commonName }),
      notBefore: date.clone().toDate(),
      notAfter: date.clone().add(attributes?.expireCA || this.expireCA, 'days').toDate(),
      signingAlgorithm: signAlgo(this.algo),
      publicKey: keys.publicKey,
      signingKey: keys.privateKey,
      extensions: [
        await x509.SubjectKeyIdentifierExtension.create(keys.publicKey),
        new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
        new x509.BasicConstraintsExtension(true, undefined, true),
        // TO-DO Add Certificate revocation list support (https://github.com/PeculiarVentures/x509/pull/20)
      ]
    });
    this.rootCert = cert;
    this.rootKeys = keys;
    this.serial = serial;
    if (isBrowser) {
      return {
        cert,
        keys
      };
    } else {
      fs.existsSync(this.dir) ? this.initPKI({ force: true }) : this.initPKI();
      const pemKeys = await keysToPem({keys, crypto});
      fs.writeFileSync(path.join(this.dir, 'ca.crt'), cert.toString('pem'));
      fs.writeFileSync(path.join(this.dir, 'private', 'ca.key'), pemKeys.privateKey);
      fs.writeFileSync(path.join(this.dir, 'index.txt'), '');
      fs.writeFileSync(path.join(this.dir, 'serial'), cert.serialNumber);
      return {
        cert,
        keys
      };
    }
  }
  async genReq({commonName = this.commonClientName, domains = this.domains, ips = this.ips, attributes, existingRootCA, existingPrivateKey} = {}) {
    const crypto = new Crypto();
    x509.cryptoProvider.set(crypto);
    // Keys for client
    const keys = await loadKeys({dir: this.dir, algo: this.algo, privateKey: existingPrivateKey, fileName: './private/' + wrapFileName(commonName) + '.key', crypto});
    // Keys, Cert from CA Certificate
    const rootCert = loadCert({thisCert: this.rootCert, dir: this.dir, certificate: existingRootCA, fileName: 'ca.crt'});
    const rootPublicKey = await rootCert.publicKey.export();
    const req = await x509.Pkcs10CertificateRequestGenerator.create({
      name: attrsWrapper(attributes ? { ...attributes, cn: commonName } : { ...this.attrs, cn: commonName }),
      keys,
      signingAlgorithm: signAlgo(this.algo),
      extensions: [
        new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.keyEncipherment),
        new x509.ExtendedKeyUsageExtension(['1.3.6.1.5.5.7.3.1', '1.3.6.1.5.5.7.3.2'], false),
        new x509.BasicConstraintsExtension(true, undefined, false),
        await x509.SubjectKeyIdentifierExtension.create(keys.publicKey),
        await x509.AuthorityKeyIdentifierExtension.create(rootPublicKey),
        new x509.SubjectAlternativeNameExtension({
          dns: domains,
          ip: ips,
        }),
        new x509.CertificatePolicyExtension(['2.23.140.1.2.1']),
      ],
    });
    const index = this.reqs.indexOf(this.reqs.find(r => r.commonName === commonName));
    if (index !== -1) {
      this.reqs[index] = {
        commonName,
        req,
        keys
      };
    } else {
      this.reqs.push({
        commonName,
        req,
        keys
      });
    }
    if (isBrowser) {
      return {
        req,
        keys
      };
    } else {
      if (!fs.existsSync(path.join(this.dir, 'reqs'))) {
        fs.mkdirSync(path.join(this.dir, 'reqs'), { recursive: true });
      }
      if (!fs.existsSync(path.join(this.dir, 'private'))) {
        fs.mkdirSync(path.join(this.dir, 'private'), { recursive: true });
      }
      const pemKeys = await keysToPem({keys, crypto});
      const fileName = wrapFileName(commonName);
      fs.writeFileSync(path.join(this.dir, 'reqs', `${fileName}.req`), req.toString('pem'));
      fs.writeFileSync(path.join(this.dir, 'private', `${fileName}.key`), pemKeys.privateKey);
      return {
        req,
        keys
      };
    }
  }
  async signReq({commonName = 'Node-RSA Client', attributes, serialNumber, serialNumberBytes = this.serialBytes, certReq, existingRootCA, existingRootKeys} = {}) {
    const crypto = new Crypto();
    const date = moment();
    x509.cryptoProvider.set(crypto);
    const rootCert = loadCert({thisCert: this.rootCert, dir: this.dir, certificate: existingRootCA, fileName: 'ca.crt'});
    const rootKeys = await loadKeys({thisKeys: this.rootKeys, dir: this.dir, algo: this.algo, privateKey: existingRootKeys, fileName: './private/ca.key', crypto, create: false});
    const req = loadReq({thisReq: this.reqs[this.reqs.indexOf(this.reqs.find(r => r.commonName === commonName))]?.req, dir: this.dir, certificateRequest: certReq, fileName: './reqs/' + wrapFileName(commonName) + '.req'});
    const certCommonName = req.subjectName.toJSON().find(n => n.CN).CN[0];
    if (commonName !== certCommonName) {
      throw new Error('commonName mismatch with certReq');
    }
    const serial = serialNumber || randomHex(serialNumberBytes);
    const subjectKey = await req.publicKey.export();
    const cert = await x509.X509CertificateGenerator.create({
      serialNumber: serial,
      subject: req.subject,
      issuer: rootCert.subject,
      notBefore: date.clone().toDate(),
      notAfter: date.clone().add(attributes?.expireCert || this.expireCert, 'days').toDate(),
      signingAlgorithm: signAlgo(this.algo),
      publicKey: subjectKey,
      signingKey: rootKeys.privateKey,
      extensions: [
        new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.keyEncipherment, true),
        new x509.ExtendedKeyUsageExtension(['1.3.6.1.5.5.7.3.1', '1.3.6.1.5.5.7.3.2'], false),
        new x509.BasicConstraintsExtension(true, undefined, true),
        await x509.SubjectKeyIdentifierExtension.create(subjectKey),
        await x509.AuthorityKeyIdentifierExtension.create(rootKeys.publicKey),
        new x509.SubjectAlternativeNameExtension(getAltNameFromReq(req)),
        new x509.CertificatePolicyExtension(['2.23.140.1.2.1']),
      ]
    });
    const index = this.reqs.indexOf(this.reqs.find(r => r.commonName === commonName));
    if (index !== -1) {
      this.reqs[index] = {
        ...this.reqs[index],
        cert
      };
    } else {
      this.reqs.push({
        commonName,
        req,
        cert,
        keys: {
          publicKey: subjectKey
        }
      });
    }
    if (isBrowser) {
      return cert;
    } else {
      if (!fs.existsSync(path.join(this.dir, 'issued'))) {
        fs.mkdirSync(path.join(this.dir, 'issued'), { recursive: true });
      }
      const wrappedName = wrapFileName(commonName);
      fs.writeFileSync(path.join(this.dir, 'issued', `${wrappedName}.crt`), cert.toString('pem'));
      return cert;
    }
  }
}

module.exports = NodeRSA;
