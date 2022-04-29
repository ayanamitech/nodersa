const x509 = require('@peculiar/x509');

const buildCA = async ({subjectKey, authorityKey}) => {
  return [
    await x509.SubjectKeyIdentifierExtension.create(subjectKey),
    await x509.AuthorityKeyIdentifierExtension.create(authorityKey),
    new x509.BasicConstraintsExtension(true, undefined, true),
    new x509.KeyUsagesExtension(x509.KeyUsageFlags.cRLSign | x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.keyCertSign, true),
    // TO-DO: Add CRLDistributionPoints for Apple MDM
  ];
};

const genReq = async ({subjectKey, authorityKey}) => {
  return [
    new x509.BasicConstraintsExtension(false, undefined, true),
    await x509.SubjectKeyIdentifierExtension.create(subjectKey),
    await x509.AuthorityKeyIdentifierExtension.create(authorityKey),
    new x509.ExtendedKeyUsageExtension(['1.3.6.1.5.5.7.3.1', '1.3.6.1.5.5.7.3.2'], true),
    new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.keyEncipherment),
    // TO-DO: Add 1.2.840.113635.100.6.10.2
  ];
};

const signReq = async ({subjectKey, authorityKey}) => {
  return [
    new x509.BasicConstraintsExtension(false, undefined, true),
    await x509.SubjectKeyIdentifierExtension.create(subjectKey),
    await x509.AuthorityKeyIdentifierExtension.create(authorityKey),
    new x509.ExtendedKeyUsageExtension(['1.3.6.1.5.5.7.3.1', '1.3.6.1.5.5.7.3.2'], true),
    new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.keyEncipherment),
    // TO-DO: Add 1.2.840.113635.100.6.10.2
  ];
};

module.exports = {
  buildCA,
  genReq,
  signReq
};
