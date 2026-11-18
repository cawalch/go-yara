package compiler

import "crypto/x509"

// Certificate pointers are owned by one scan's parsed signatures. Sharing this
// cache across leaf, certificate-array, and chain views avoids duplicate work.
// Separate loaded/defined bits also memoize malformed, undefined fields.
type peCertificateFields struct {
	values  [6]string
	loaded  uint8
	defined uint8
}

func certificateFieldIndex(field string) int {
	switch field {
	case "issuer":
		return 0
	case "subject":
		return 1
	case "serial":
		return 2
	case "thumbprint":
		return 3
	case "algorithm":
		return 4
	case "algorithm_oid":
		return 5
	default:
		return -1
	}
}

func (image *peImage) certificateField(cert *x509.Certificate, field string) ModuleValue {
	index := certificateFieldIndex(field)
	if cert == nil || index < 0 {
		return peCertificateField(cert, field)
	}
	sigs := image.loadSignatures()
	if sigs.certificateFields == nil {
		sigs.certificateFields = make(map[*x509.Certificate]*peCertificateFields)
	}
	cached := sigs.certificateFields[cert]
	if cached == nil {
		cached = &peCertificateFields{}
		sigs.certificateFields[cert] = cached
	}
	bit := uint8(1) << index
	if cached.loaded&bit == 0 {
		cached.loaded |= bit
		value := peCertificateField(cert, field)
		if value.Type == ModuleString {
			cached.defined |= bit
			cached.values[index] = value.String
		}
	}
	if cached.defined&bit == 0 {
		return ModuleValue{}
	}
	return StringValue(cached.values[index])
}
