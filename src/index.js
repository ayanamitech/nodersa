const x509 = require('@peculiar/x509');
const { Crypto } = require('@peculiar/webcrypto');
const moment = require('moment');
const randomHex = require('@ayanamitech/randomhex');

const fs = require('fs');
const path = require('path');
const process = require('process');

const { isBrowser, keysToPem, loadKeys, loadCert, loadReq, loadSerial, wrapFileName } = require('./utils');
const { signAlgo } = require('./algo');
const attrsWrapper = require('./attrs');
const templates = require('./templates');

class NodeRSA {
  constructor(options) {
    /**
      Template:

      mdm: Could be used to generate certificates for mobile devices

      https://developer.apple.com/documentation/devicemanagement/implementing_device_management/managing_certificates_for_mdm_servers_and_devices

      ssl: Could be used to generate certificate for web servers

      vpn: Could be used to generate EasyRSA like certificate for VPN certificate
    **/
    this.template = 'ssl';
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
  async buildCA({template = this.template, commonName = this.commonName, attributes, serialNumber = this.serial, serialNumberBytes = this.serialBytes, existingPrivateKey} = {}) {
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
      extensions: await templates[template].buildCA({subjectKey: keys.publicKey, authorityKey: keys.publicKey}),
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
  async genReq({template = this.template, type = 'server', commonName = this.commonClientName, domains = this.domains, ips = this.ips, attributes, existingRootCA, existingPrivateKey} = {}) {
    const crypto = new Crypto();
    x509.cryptoProvider.set(crypto);
    // Keys for client
    const keys = await loadKeys({dir: this.dir, algo: this.algo, privateKey: existingPrivateKey, fileName: './private/' + wrapFileName(commonName) + '.key', crypto});
    // Keys, Cert from CA Certificate
    const rootCert = loadCert({thisCert: this.rootCert, dir: this.dir, certificate: existingRootCA, fileName: 'ca.crt'});
    const authorityKey = await rootCert.publicKey.export();
    const req = await x509.Pkcs10CertificateRequestGenerator.create({
      name: attrsWrapper(attributes ? { ...attributes, cn: commonName } : { ...this.attrs, cn: commonName }),
      keys,
      signingAlgorithm: signAlgo(this.algo),
      extensions: await templates[template].genReq((template === 'ssl') ? {subjectKey: keys.publicKey, authorityKey, domains, ips} : (template === 'vpn') ? {subjectKey: keys.publicKey, authorityKey, type} : {subjectKey: keys.publicKey, authorityKey}),
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
  async signReq({template = this.template, type = 'server', commonName = 'Node-RSA Client', attributes, serialNumber, serialNumberBytes = this.serialBytes, certReq, existingRootCA, existingRootKeys} = {}) {
    const crypto = new Crypto();
    const date = moment();
    x509.cryptoProvider.set(crypto);
    /**
    TO-DO: Handle renewal with cert revoke list
    Below code is working btw
    const loadIssuedCert = () => {
      try {
        return loadCert({thisCert: this.reqs[this.reqs.indexOf(this.reqs.find(r => r.commonName === commonName))]?.cert, dir: this.dir, fileName: './issued/' + wrapFileName(commonName) + '.crt'});
      } catch (err) {
        return {};
      }
    };
    const issuedCert = loadIssuedCert();
    if (Object.keys(issuedCert).length > 0 && moment(issuedCert.notAfter).clone().subtract(30, 'days').utc().valueOf() > moment().utc().valueOf()) {
      console.log('Certificate', commonName, 'not due <' +  moment(issuedCert.notAfter).clone().subtract(30, 'days').toDate() + '> for renewal');
      return {
        cert: issuedCert,
        issued: false
      };
    }
    **/
    const rootCert = loadCert({thisCert: this.rootCert, dir: this.dir, certificate: existingRootCA, fileName: 'ca.crt'});
    const rootKeys = await loadKeys({thisKeys: this.rootKeys, dir: this.dir, algo: this.algo, privateKey: existingRootKeys, fileName: './private/ca.key', crypto, create: false});
    const req = loadReq({thisReq: this.reqs[this.reqs.indexOf(this.reqs.find(r => r.commonName === commonName))]?.req, dir: this.dir, certificateRequest: certReq, fileName: './reqs/' + wrapFileName(commonName) + '.req'});
    const certCommonName = req.subjectName.toJSON().find(n => n.CN).CN[0];
    if (commonName !== certCommonName) {
      throw new Error('commonName mismatch with certReq');
    }
    const serial = loadSerial({thisSerial: this.serial, dir: this.dir, serialNumber, serialNumberBytes, fileName: 'serial'});
    const certSerial = serial.length % 2 ? `0${serial}` : serial;
    const subjectKey = await req.publicKey.export();
    const cert = await x509.X509CertificateGenerator.create({
      serialNumber: certSerial,
      subject: req.subject,
      issuer: rootCert.subject,
      notBefore: date.clone().toDate(),
      notAfter: date.clone().add(attributes?.expireCert || this.expireCert, 'days').toDate(),
      signingAlgorithm: signAlgo(this.algo),
      publicKey: subjectKey,
      signingKey: rootKeys.privateKey,
      extensions: await templates[template].signReq((template === 'ssl') ? {subjectKey, authorityKey: rootKeys.publicKey, req} : (template === 'vpn') ? {subjectKey, authorityKey: rootKeys.publicKey, type} : {subjectKey, authorityKey: rootKeys.publicKey}),
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
    this.serial = certSerial;
    if (isBrowser) {
      return { cert };
    } else {
      if (!fs.existsSync(path.join(this.dir, 'issued'))) {
        fs.mkdirSync(path.join(this.dir, 'issued'), { recursive: true });
      }
      // to-do complete index for openssl https://github.com/mgcrea/node-easyrsa/blob/master/src/index.js#L188
      //const fileIndex = fs.existsSync(path.join(this.dir, 'index.txt')) ? fs.readFileSync(path.join(this.dir, 'index.txt')).toString() : '';
      const wrappedName = wrapFileName(commonName);
      fs.writeFileSync(path.join(this.dir, 'certs_by_serial', `${certSerial}.pem`), cert.toString('pem'));
      fs.writeFileSync(path.join(this.dir, 'issued', `${wrappedName}.crt`), cert.toString('pem'));
      fs.writeFileSync(path.join(this.dir, 'serial'), certSerial);
      return { cert };
    }
  }
}

module.exports = NodeRSA;
