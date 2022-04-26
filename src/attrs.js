/**
  Return WebCrypto compatible attributes
**/
const asn1X509 = require('@peculiar/asn1-x509');
const x509 = require('@peculiar/x509');

const asnWrapper = (attrValue) => {
  return new asn1X509.RelativeDistinguishedName([
    new asn1X509.AttributeTypeAndValue({
      type: attrValue.type,
      value: new asn1X509.AttributeValue({ printableString: attrValue.value })
    }),
  ]);
};

/**
  Type from http://oidref.com/2.5.4

  https://github.com/DefinitelyTyped/DefinitelyTyped/blob/f7ec78508c6797e42f87a4390735bc2c650a1bfd/types/jsrsasign/modules/KJUR/asn1/x509/OID.d.ts
**/
const attrsWrapper = (attrs) => {
  const nameArray = [];

  // Country name
  if (attrs?.country) {
    nameArray.push(asnWrapper({ type: '2.5.4.6', value: attrs.country }));
  }
  // State or Province name
  if (attrs?.province) {
    nameArray.push(asnWrapper({ type: '2.5.4.8', value: attrs.province }));
  }
  // Locality Name
  if (attrs?.city) {
    nameArray.push(asnWrapper({ type: '2.5.4.7', value: attrs.city }));
  }
  // Organization name
  if (attrs?.org) {
    nameArray.push(asnWrapper({ type: '2.5.4.10', value: attrs.org }));
  }
  // Common Name
  if (attrs?.email) {
    nameArray.push(asnWrapper({ type: '1.2.840.113549.1.9.1', value: attrs.email }));
  }
  // Organization unit name
  if (attrs?.ou) {
    nameArray.push(asnWrapper({ type: '2.5.4.11', value: attrs.ou }));
  }
  // Common name
  if (attrs?.cn) {
    nameArray.push(asnWrapper({ type: '2.5.4.3', value: attrs.cn }));
  }

  const name = new asn1X509.Name(nameArray);
  return new x509.Name(name).toString();
};

module.exports = attrsWrapper;
