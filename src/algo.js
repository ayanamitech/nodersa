/**
  Return OpenSSL (EasyRSA) style properties to WebCrypto (Node.js) compatible format
**/

const rsaWrapper = (digest) => {
  switch (digest) {
  case 'md5':
    throw new Error('RSA Digest not supported');
  case 'sha1':
    return 'SHA-1';
  case 'sha256':
    return 'SHA-256';
  case 'sha224':
    throw new Error('RSA Digest not supported');
  case 'sha384':
    return 'SHA-384';
  case 'sha512':
    return 'SHA-512';
  default:
    return 'SHA-256';
  }
};

const ecWrapper = (curve) => {
  switch (curve) {
  case 'prime256v1':
    return 'P-256';
  case 'secp384r1':
    return 'P-384';
  case 'secp521r1':
    return 'P-521';
  default:
    return 'P-384';
  }
};

const edWrapper = (curve) => {
  switch (curve) {
  case 'ED25519':
    return 'Ed25519';
  case 'ED448':
    return 'Ed448';
  default:
    return 'Ed25519';
  }
};

/**
  Return parameters required by WebCrypto specification

  https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/generateKey

  Could be used with:

  crypto.subtle.generateKey
  crypto.subtle.importKey
**/
const generateAlgo = (algo) => {
  switch (algo.algo) {
  case 'rsa':
    return {
      name: 'RSASSA-PKCS1-v1_5',
      hash: rsaWrapper(algo.digest),
      publicExponent: new Uint8Array([1, 0, 1]),
      modulusLength: algo.keysize
    };
  case 'ec':
    return {
      name: 'ECDSA',
      namedCurve: ecWrapper(algo.curve)
    };
  case 'ed':
    return {
      name: 'EdDSA',
      namedCurve: edWrapper(algo.curve)
    };
  default:
    return {
      name: 'RSASSA-PKCS1-v1_5',
      hash: rsaWrapper(algo.digest),
      publicExponent: new Uint8Array([1, 0, 1]),
      modulusLength: algo.keysize
    };
  }
};

/**
  Return parameters required by WebCrypto specification

  https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/sign

  Could be used with:

  crypto.subtle.sign
  crypto.subtle.verify
**/
const signAlgo = (algo) => {
  switch (algo.algo) {
  case 'rsa':
    return {
      name: 'RSASSA-PKCS1-v1_5'
    };
  case 'ec':
    return {
      name: 'ECDSA',
      hash: rsaWrapper(algo.digest)
    };
  case 'ed':
    return {
      name: 'EdDSA'
    };
  default:
    return {
      name: 'RSASSA-PKCS1-v1_5'
    };
  }
};

module.exports = {
  generateAlgo,
  signAlgo
};
