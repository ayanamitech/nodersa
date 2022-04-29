const x509 = require('@peculiar/x509');
const { getAltNameFromReq } = require('../utils');

const buildCA = async ({subjectKey, authorityKey}) => {
  return [
    await x509.SubjectKeyIdentifierExtension.create(subjectKey),
    await x509.AuthorityKeyIdentifierExtension.create(authorityKey),
    new x509.BasicConstraintsExtension(true, undefined, true),
    new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
  ];
};

const genReq = async ({subjectKey, authorityKey, domains, ips}) => {
  return [
    new x509.BasicConstraintsExtension(false, undefined, false),
    await x509.SubjectKeyIdentifierExtension.create(subjectKey),
    await x509.AuthorityKeyIdentifierExtension.create(authorityKey),
    new x509.ExtendedKeyUsageExtension(['1.3.6.1.5.5.7.3.1', '1.3.6.1.5.5.7.3.2'], false),
    new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.keyEncipherment),
    new x509.SubjectAlternativeNameExtension({
      dns: domains,
      ip: ips,
    }),
    new x509.CertificatePolicyExtension(['2.23.140.1.2.1']),
  ];
};

const signReq = async ({subjectKey, authorityKey, req}) => {
  return [
    new x509.BasicConstraintsExtension(false, undefined, false),
    await x509.SubjectKeyIdentifierExtension.create(subjectKey),
    await x509.AuthorityKeyIdentifierExtension.create(authorityKey),
    new x509.ExtendedKeyUsageExtension(['1.3.6.1.5.5.7.3.1', '1.3.6.1.5.5.7.3.2'], false),
    new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.keyEncipherment),
    new x509.SubjectAlternativeNameExtension(getAltNameFromReq(req)),
    new x509.CertificatePolicyExtension(['2.23.140.1.2.1']),
  ];
};

module.exports = {
  buildCA,
  genReq,
  signReq
};
