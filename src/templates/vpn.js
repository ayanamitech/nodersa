const x509 = require('@peculiar/x509');

const buildCA = async ({subjectKey, authorityKey}) => {
  return [
    await x509.SubjectKeyIdentifierExtension.create(subjectKey),
    await x509.AuthorityKeyIdentifierExtension.create(authorityKey),
    new x509.BasicConstraintsExtension(true, undefined, false),
    new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
  ];
};

const genReq = async ({subjectKey, authorityKey, type}) => {
  const extension = [
    new x509.BasicConstraintsExtension(false, undefined, false),
    await x509.SubjectKeyIdentifierExtension.create(subjectKey),
    await x509.AuthorityKeyIdentifierExtension.create(authorityKey),
  ];
  switch (type) {
  case 'server':
    return [
      ...extension,
      new x509.ExtendedKeyUsageExtension(['1.3.6.1.5.5.7.3.1'], false),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.keyEncipherment),
    ];
  case 'client':
    return [
      ...extension,
      new x509.ExtendedKeyUsageExtension(['1.3.6.1.5.5.7.3.2'], false),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature),
    ];
  default:
    throw new Error('Type not supported');
  }
};

const signReq = async ({subjectKey, authorityKey, type}) => {
  const extension = [
    new x509.BasicConstraintsExtension(false, undefined, false),
    await x509.SubjectKeyIdentifierExtension.create(subjectKey),
    await x509.AuthorityKeyIdentifierExtension.create(authorityKey),
  ];
  switch (type) {
  case 'server':
    return [
      ...extension,
      new x509.ExtendedKeyUsageExtension(['1.3.6.1.5.5.7.3.1'], false),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.keyEncipherment),
    ];
  case 'client':
    return [
      ...extension,
      new x509.ExtendedKeyUsageExtension(['1.3.6.1.5.5.7.3.2'], false),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature),
    ];
  default:
    throw new Error('Type not supported');
  }
};

module.exports = {
  buildCA,
  genReq,
  signReq
};
