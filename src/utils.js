const x509 = require('@peculiar/x509');
const { Crypto } = require('@peculiar/webcrypto');
const fs = require('fs');
const path = require('path');
const { generateAlgo } = require('./algo');

const isBrowser = typeof window !== 'undefined';

const checkPem = (raw) => {
  if (typeof raw === 'string') {
    return x509.PemConverter.isPem(raw);
  }
  // Parse Buffer (Node.js Only)
  // Example: fs.readFileSync('pem')
  if (!isBrowser && typeof raw === 'object' && Buffer.isBuffer(raw)) {
    return x509.PemConverter.isPem(raw.toString());
  }
  return x509.PemConverter.isPem(raw);
};

const keysToPem = async ({keys, crypto}) => {
  if (!crypto) {
    crypto = new Crypto();
  }
  return {
    publicKey: x509.PemConverter.encode(await crypto.subtle.exportKey('spki', keys.publicKey), 'PUBLIC KEY'),
    privateKey: x509.PemConverter.encode(await crypto.subtle.exportKey('pkcs8', keys.privateKey), 'PRIVATE KEY')
  };
};

const getPublicFromPrivate = async ({privateKey, algo, crypto}) => {
  if (!crypto) {
    crypto = new Crypto();
  }
  const exported = await crypto.subtle.exportKey('jwk', privateKey);
  delete exported.d;
  delete exported.dp;
  delete exported.dq;
  delete exported.q;
  delete exported.qi;
  exported.key_ops = ['sign', 'verify'];
  const publicKey = await crypto.subtle.importKey('jwk', exported, generateAlgo(algo), true, ['sign', 'verify']);
  return publicKey;
};

const pemToKey = async ({private, algo, crypto}) => {
  if (!crypto) {
    crypto = new Crypto();
  }
  const privateKey = await crypto.subtle.importKey('pkcs8', x509.PemConverter.decode(private, 'PRIVATE KEY')[0], generateAlgo(algo), true, ['sign', 'verify']);
  const publicKey = await getPublicFromPrivate({privateKey, algo, crypto});
  return {
    publicKey,
    privateKey
  };
};

const loadKeys = async ({thisKeys, dir, algo, privateKey, fileName, crypto, create = true}) => {
  if (thisKeys && Object.keys(thisKeys).length > 0) {
    return thisKeys;
  }
  if (!crypto) {
    crypto = new Crypto();
  }
  if (privateKey && checkPem(privateKey)) {
    return await pemToKey({private: privateKey, algo, crypto});
  }
  if (!isBrowser && fileName && fs.existsSync(path.join(dir, fileName)) && checkPem(fs.readFileSync(path.join(dir, fileName)))) {
    return await pemToKey({private: fs.readFileSync(path.join(dir, fileName)), algo, crypto});
  }
  if (create) {
    return await crypto.subtle.generateKey(generateAlgo(algo), true, ['sign', 'verify']);
  }
  throw new Error('Keys not found');
};

const loadCert = ({thisCert, dir, certificate, fileName}) => {
  if (thisCert && Object.keys(thisCert).length > 0) {
    return thisCert;
  }
  if (certificate && checkPem(certificate)) {
    return new x509.X509Certificate(certificate);
  }
  if (!isBrowser && fileName && fs.existsSync(path.join(dir, fileName)) && checkPem(fs.readFileSync(path.join(dir, fileName)))) {
    return new x509.X509Certificate(fs.readFileSync(path.join(dir, fileName)));
  }
  throw new Error('Certificate not found');
};

const loadReq = ({thisReq, dir, certificateRequest, fileName}) => {
  if (thisReq && Object.keys(thisReq).length > 0) {
    return thisReq;
  }
  if (certificateRequest && checkPem(certificateRequest)) {
    return new x509.Pkcs10CertificateRequest(certificateRequest);
  }
  if (!isBrowser && fileName && fs.existsSync(path.join(dir, fileName)) && checkPem(fs.readFileSync(path.join(dir, fileName)))) {
    return new x509.Pkcs10CertificateRequest(fs.readFileSync(path.join(dir, fileName)));
  }
  throw new Error('Certificate Request not found');
};

const wrapFileName = (fileName) => {
  return fileName.replace(/\*/g, 'wildcard-record');
};

const unwrapFileName = (fileName) => {
  return fileName.replace(/\wildcard-record/g, '*');
};

const getAltNameFromReq = (req) => {
  const extensionRequest = req.getAttributes('1.2.840.113549.1.9.14');
  // Try parsing subjectAltName from extensionRequest attributes
  if (extensionRequest.length > 0 && extensionRequest[0].items.find(e => e.type === '2.5.29.17')) {
    return extensionRequest[0].items.find(e => e.type === '2.5.29.17').toJSON();
  }
  return null;
};

module.exports = {
  isBrowser,
  checkPem,
  keysToPem,
  pemToKey,
  getPublicFromPrivate,
  loadKeys,
  loadCert,
  loadReq,
  wrapFileName,
  unwrapFileName,
  getAltNameFromReq
};
