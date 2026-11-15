package compiler

import (
	"bytes"
	"crypto/sha1" // #nosec G505 -- YARA compatibility requires SHA-1 certificate thumbprints.
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"maps"
	"strings"

	pe "github.com/cawalch/go-pe"
)

func newPECertificateSchema() *ModuleSchema {
	return &ModuleSchema{Fields: map[string]ModuleField{
		"issuer":        {Kind: ModuleString},
		"subject":       {Kind: ModuleString},
		"version":       {Kind: ModuleInteger},
		"algorithm":     {Kind: ModuleString},
		"algorithm_oid": {Kind: ModuleString},
		"serial":        {Kind: ModuleString},
		"thumbprint":    {Kind: ModuleString},
		"not_before":    {Kind: ModuleInteger},
		"not_after":     {Kind: ModuleInteger},
	}}
}

func newPESignaturesSchema() *ModuleSchema {
	fields := maps.Clone(peOverlaySchema.Fields)
	certSchema := newPECertificateSchema()
	sigFields := maps.Clone(certSchema.Fields)
	sigFields["digest"] = ModuleField{Kind: ModuleString}
	sigFields["digest_alg"] = ModuleField{Kind: ModuleString}
	sigFields["number_of_certificates"] = ModuleField{Kind: ModuleInteger}
	sigFields["certificates"] = ModuleField{
		Kind:    ModuleArray,
		Element: &ModuleField{Kind: ModuleStruct, Struct: certSchema},
	}
	sigFields["signer_info"] = ModuleField{
		Kind: ModuleStruct,
		Struct: &ModuleSchema{Fields: map[string]ModuleField{
			"program_name":    {Kind: ModuleString},
			"digest":          {Kind: ModuleString},
			"digest_alg":      {Kind: ModuleString},
			"length_of_chain": {Kind: ModuleInteger},
			"chain": {
				Kind:    ModuleArray,
				Element: &ModuleField{Kind: ModuleStruct, Struct: certSchema},
			},
		}},
	}
	sigFields["number_of_countersignatures"] = ModuleField{Kind: ModuleInteger}
	sigFields["countersignatures"] = ModuleField{
		Kind: ModuleArray,
		Element: &ModuleField{
			Kind: ModuleStruct,
			Struct: &ModuleSchema{Fields: map[string]ModuleField{
				"digest":          {Kind: ModuleString},
				"digest_alg":      {Kind: ModuleString},
				"sign_time":       {Kind: ModuleInteger},
				"length_of_chain": {Kind: ModuleInteger},
				"chain": {
					Kind:    ModuleArray,
					Element: &ModuleField{Kind: ModuleStruct, Struct: certSchema},
				},
			}},
		},
	}

	fields["number_of_signatures"] = ModuleField{Kind: ModuleInteger}
	fields["signatures"] = ModuleField{
		Kind:    ModuleArray,
		Element: &ModuleField{Kind: ModuleStruct, Struct: &ModuleSchema{Fields: sigFields}},
	}
	return &ModuleSchema{Fields: fields}
}

// Signature parsing errors leave header fields intact and signature metadata
// undefined. A non-nil cache records both success and failure so repeated rule
// references within the same scan never re-parse CMS blobs.
type peSignatureData struct {
	signatures []pe.AuthenticodeSignature
	details    ModuleValue
	valid      bool
}

func (image *peImage) loadSignatures() *peSignatureData {
	if image.signatures == nil {
		done := peCancelDone(image.context)
		if scanCanceled(done) {
			return &peSignatureData{}
		}
		sigs, err := image.file.AuthenticodeSignatures(peScanData(image.context))
		if err != nil {
			image.signatures = &peSignatureData{}
			return image.signatures
		}
		if scanCanceled(done) {
			return &peSignatureData{}
		}
		image.signatures = &peSignatureData{
			signatures: sigs,
			valid:      true,
		}
	}
	return image.signatures
}

func (image *peImage) signatureField(name string) ModuleValue {
	data := image.loadSignatures()
	if !data.valid {
		return ModuleValue{}
	}
	switch name {
	case "number_of_signatures":
		return IntegerValue(int64(len(data.signatures)))
	case "signatures":
		if data.details.Type == ModuleUndefined {
			values := make([]ModuleValue, len(data.signatures))
			for i := range data.signatures {
				values[i] = peSignatureValue(data.signatures[i])
			}
			data.details = peArray(values)
		}
		return data.details
	}
	return ModuleValue{}
}

func peSignatureValue(sig pe.AuthenticodeSignature) ModuleValue {
	var signer *pe.AuthenticodeSigner
	if len(sig.Signers) > 0 {
		signer = &sig.Signers[0]
	}

	var (
		leafLoaded bool
		leafCert   *x509.Certificate
	)
	resolveLeaf := func() *x509.Certificate {
		if !leafLoaded {
			leafLoaded = true
			if signer != nil {
				leafCert = peMatchSignerCert(signer, sig.Certificates)
			}
		}
		return leafCert
	}

	allCertsCount := len(sig.Certificates)
	if signer != nil {
		for i := range signer.Timestamps {
			if signer.Timestamps[i].Kind == pe.AuthenticodeTimestampRFC3161 {
				allCertsCount += len(signer.Timestamps[i].Certificates)
			}
		}
	}

	var (
		certsArray           ModuleValue
		signerInfoVal        ModuleValue
		countersignaturesVal ModuleValue
	)

	return peLazyStruct(func(field string) ModuleValue {
		switch field {
		case "issuer", "subject", "version", "algorithm", "algorithm_oid",
			"serial", "thumbprint", "not_before", "not_after":
			return peCertificateField(resolveLeaf(), field)
		case "digest":
			if sig.IndirectData != nil && len(sig.IndirectData.Digest) > 0 {
				return StringValue(hex.EncodeToString(sig.IndirectData.Digest))
			}
		case "digest_alg":
			if sig.IndirectData != nil && len(sig.IndirectData.DigestAlgorithm.Algorithm) > 0 {
				return StringValue(peDigestAlgorithmName(sig.IndirectData.DigestAlgorithm.Algorithm))
			}
		case "number_of_certificates":
			return IntegerValue(int64(allCertsCount))
		case "certificates":
			if certsArray.Type == ModuleUndefined {
				certs := make([]*x509.Certificate, 0, allCertsCount)
				certs = append(certs, sig.Certificates...)
				if signer != nil {
					for i := range signer.Timestamps {
						if signer.Timestamps[i].Kind == pe.AuthenticodeTimestampRFC3161 {
							certs = append(certs, signer.Timestamps[i].Certificates...)
						}
					}
				}
				certsArray = peCertificateArray(certs)
			}
			return certsArray
		case "signer_info":
			if signerInfoVal.Type == ModuleUndefined {
				signerInfoVal = peSignerInfoValue(signer, sig.Certificates)
			}
			return signerInfoVal
		case "number_of_countersignatures":
			if signer == nil {
				return IntegerValue(0)
			}
			return IntegerValue(int64(len(signer.Timestamps)))
		case "countersignatures":
			if countersignaturesVal.Type == ModuleUndefined {
				if signer == nil || len(signer.Timestamps) == 0 {
					countersignaturesVal = peArray(nil)
				} else {
					elements := make([]ModuleValue, len(signer.Timestamps))
					for i := range signer.Timestamps {
						elements[i] = peCountersignatureValue(signer.Timestamps[i], sig.Certificates)
					}
					countersignaturesVal = peArray(elements)
				}
			}
			return countersignaturesVal
		}
		return ModuleValue{}
	})
}

func peSignerInfoValue(signer *pe.AuthenticodeSigner, pool []*x509.Certificate) ModuleValue {
	var (
		chainLoaded bool
		chain       []*x509.Certificate
		chainArray  ModuleValue
	)
	resolveChain := func() []*x509.Certificate {
		if !chainLoaded {
			chainLoaded = true
			if signer != nil {
				chain = peBuildCertChain(signer, pool)
			}
		}
		return chain
	}
	return peLazyStruct(func(field string) ModuleValue {
		switch field {
		case "program_name":
			if signer != nil && signer.OpusInfo != nil && signer.OpusInfo.ProgramName != "" {
				return StringValue(signer.OpusInfo.ProgramName)
			}
		case "digest":
			if signer != nil && len(signer.MessageDigest) > 0 {
				return StringValue(hex.EncodeToString(signer.MessageDigest))
			}
		case "digest_alg":
			if signer != nil && len(signer.MessageDigest) > 0 && len(signer.DigestAlgorithm.Algorithm) > 0 {
				return StringValue(peDigestAlgorithmName(signer.DigestAlgorithm.Algorithm))
			}
		case "length_of_chain":
			return IntegerValue(int64(len(resolveChain())))
		case "chain":
			if chainArray.Type == ModuleUndefined {
				chainArray = peCertificateArray(resolveChain())
			}
			return chainArray
		}
		return ModuleValue{}
	})
}

func peCountersignatureValue(ts pe.AuthenticodeTimestamp, outerCerts []*x509.Certificate) ModuleValue {
	var tsSigner *pe.AuthenticodeSigner
	if len(ts.Signers) > 0 {
		tsSigner = &ts.Signers[0]
	}
	var (
		chainLoaded bool
		chain       []*x509.Certificate
		chainArray  ModuleValue
	)
	resolveChain := func() []*x509.Certificate {
		if !chainLoaded {
			chainLoaded = true
			pool := outerCerts
			if ts.Kind == pe.AuthenticodeTimestampRFC3161 {
				pool = ts.Certificates
			}
			chain = peBuildCertChain(tsSigner, pool)
		}
		return chain
	}
	return peLazyStruct(func(field string) ModuleValue {
		switch field {
		case "sign_time":
			if ts.HasSigningTime {
				return IntegerValue(ts.SigningTime.Unix())
			}
		case "digest":
			if ts.Kind == pe.AuthenticodeTimestampRFC3161 {
				if len(ts.Digest) > 0 {
					return StringValue(hex.EncodeToString(ts.Digest))
				}
			} else if tsSigner != nil && len(tsSigner.MessageDigest) > 0 {
				return StringValue(hex.EncodeToString(tsSigner.MessageDigest))
			}
		case "digest_alg":
			if ts.Kind == pe.AuthenticodeTimestampRFC3161 {
				if len(ts.DigestAlgorithm.Algorithm) > 0 {
					return StringValue(peDigestAlgorithmName(ts.DigestAlgorithm.Algorithm))
				}
			} else if tsSigner != nil && len(tsSigner.DigestAlgorithm.Algorithm) > 0 {
				return StringValue(peDigestAlgorithmName(tsSigner.DigestAlgorithm.Algorithm))
			}
		case "length_of_chain":
			return IntegerValue(int64(len(resolveChain())))
		case "chain":
			if chainArray.Type == ModuleUndefined {
				chainArray = peCertificateArray(resolveChain())
			}
			return chainArray
		}
		return ModuleValue{}
	})
}

func peCertificateArray(certs []*x509.Certificate) ModuleValue {
	if len(certs) == 0 {
		return peArray(nil)
	}
	elements := make([]ModuleValue, len(certs))
	for i, cert := range certs {
		c := cert
		elements[i] = peLazyStruct(func(field string) ModuleValue {
			return peCertificateField(c, field)
		})
	}
	return peArray(elements)
}

func peCertificateField(cert *x509.Certificate, field string) ModuleValue {
	if cert == nil {
		return ModuleValue{}
	}
	switch field {
	case "issuer":
		if dn, ok := peFormatDistinguishedName(cert.RawIssuer); ok {
			return StringValue(dn)
		}
	case "subject":
		if dn, ok := peFormatDistinguishedName(cert.RawSubject); ok {
			return StringValue(dn)
		}
	case "version":
		return IntegerValue(int64(cert.Version))
	case "algorithm":
		if oid := peCertSignatureAlgorithmOID(cert); len(oid) > 0 {
			return StringValue(peSignatureAlgorithmName(oid))
		}
	case "algorithm_oid":
		if oid := peCertSignatureAlgorithmOID(cert); len(oid) > 0 {
			return StringValue(oid.String())
		}
	case "serial":
		serialBytes, err := pe.CertificateSerialBytes(cert)
		if err != nil || len(serialBytes) == 0 {
			return ModuleValue{}
		}
		return StringValue(peFormatColonHex(serialBytes))
	case "thumbprint":
		if len(cert.Raw) == 0 {
			return ModuleValue{}
		}
		sum := sha1.Sum(cert.Raw) // #nosec G401 -- YARA compatibility requires SHA-1 certificate thumbprints.
		return StringValue(hex.EncodeToString(sum[:]))
	case "not_before":
		return IntegerValue(cert.NotBefore.Unix())
	case "not_after":
		return IntegerValue(cert.NotAfter.Unix())
	}
	return ModuleValue{}
}

func peMatchSignerCert(signer *pe.AuthenticodeSigner, pool []*x509.Certificate) *x509.Certificate {
	if signer == nil || len(pool) == 0 {
		return nil
	}
	if len(signer.IssuerRaw) > 0 || signer.SerialNumber != nil || len(signer.SerialBytes) > 0 {
		return peMatchCertByIssuerAndSerial(signer, pool)
	}
	if len(signer.SubjectKeyID) > 0 {
		for _, cert := range pool {
			if cert != nil && bytes.Equal(cert.SubjectKeyId, signer.SubjectKeyID) {
				return cert
			}
		}
	}
	return nil
}

func peMatchCertByIssuerAndSerial(signer *pe.AuthenticodeSigner, pool []*x509.Certificate) *x509.Certificate {
	for _, cert := range pool {
		if cert == nil || !bytes.Equal(cert.RawIssuer, signer.IssuerRaw) {
			continue
		}
		if len(signer.SerialBytes) > 0 {
			if certSerial, err := pe.CertificateSerialBytes(cert); err == nil && bytes.Equal(certSerial, signer.SerialBytes) {
				return cert
			}
		}
		if signer.SerialNumber != nil && cert.SerialNumber != nil && cert.SerialNumber.Cmp(signer.SerialNumber) == 0 {
			return cert
		}
	}
	return nil
}

func peBuildCertChain(signer *pe.AuthenticodeSigner, pool []*x509.Certificate) []*x509.Certificate {
	leaf := peMatchSignerCert(signer, pool)
	if leaf == nil {
		return nil
	}
	chain := make([]*x509.Certificate, 1, min(len(pool), 8))
	chain[0] = leaf
	visited := make([]bool, len(pool))
	for i, c := range pool {
		if c == leaf {
			visited[i] = true
			break
		}
	}
	for len(chain) < len(pool) {
		cur := chain[len(chain)-1]
		if bytes.Equal(cur.RawIssuer, cur.RawSubject) {
			break
		}
		var next *x509.Certificate
		for i, c := range pool {
			if !visited[i] && c != nil && bytes.Equal(c.RawSubject, cur.RawIssuer) {
				visited[i] = true
				next = c
				break
			}
		}
		if next == nil {
			break
		}
		chain = append(chain, next)
	}
	return chain
}

func peCertSignatureAlgorithmOID(cert *x509.Certificate) asn1.ObjectIdentifier {
	if cert == nil || len(cert.Raw) == 0 {
		return nil
	}
	var rawCert struct {
		TBS       asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}
	if _, err := asn1.Unmarshal(cert.Raw, &rawCert); err != nil {
		return nil
	}
	return rawCert.Algorithm.Algorithm
}

func peFormatColonHex(b []byte) string {
	const hexDigits = "0123456789abcdef"
	buf := make([]byte, len(b)*3-1)
	for i, v := range b {
		if i > 0 {
			buf[i*3-1] = ':'
		}
		off := i * 3
		buf[off] = hexDigits[v>>4]
		buf[off+1] = hexDigits[v&0x0f]
	}
	return string(buf)
}

func peFormatDistinguishedName(raw []byte) (string, bool) {
	if len(raw) == 0 {
		return "", false
	}
	var rdnSeq pkix.RDNSequence
	rest, err := asn1.Unmarshal(raw, &rdnSeq)
	if err != nil || len(rest) > 0 {
		return "", false
	}
	if len(rdnSeq) == 0 {
		return "", true
	}
	var out strings.Builder
	for _, rdn := range rdnSeq {
		out.WriteByte('/')
		for j, atv := range rdn {
			if j > 0 {
				out.WriteByte('+')
			}
			out.WriteString(peX509AttributeName(atv.Type))
			out.WriteByte('=')
			var s string
			switch v := atv.Value.(type) {
			case string:
				s = v
			case []byte:
				s = string(v)
			}
			peWriteOnelineEscaped(&out, s)
		}
	}
	return out.String(), true
}

func peWriteOnelineEscaped(out *strings.Builder, s string) {
	const upperHex = "0123456789ABCDEF"
	for i := range len(s) {
		b := s[i]
		if b < 0x20 || b > 0x7e {
			out.WriteString(`\x`)
			out.WriteByte(upperHex[b>>4])
			out.WriteByte(upperHex[b&0x0f])
			continue
		}
		out.WriteByte(b)
	}
}

var peX509ShortNames = map[string]string{
	"2.5.4.3":                    "CN",
	"2.5.4.4":                    "SN",
	"2.5.4.5":                    "serialNumber",
	"2.5.4.6":                    "C",
	"2.5.4.7":                    "L",
	"2.5.4.8":                    "ST",
	"2.5.4.9":                    "street",
	"2.5.4.10":                   "O",
	"2.5.4.11":                   "OU",
	"2.5.4.12":                   "title",
	"2.5.4.13":                   "description",
	"2.5.4.15":                   "businessCategory",
	"2.5.4.17":                   "postalCode",
	"2.5.4.18":                   "postOfficeBox",
	"2.5.4.20":                   "telephoneNumber",
	"2.5.4.41":                   "name",
	"2.5.4.42":                   "GN",
	"2.5.4.43":                   "initials",
	"2.5.4.44":                   "generationQualifier",
	"2.5.4.45":                   "x500UniqueIdentifier",
	"2.5.4.46":                   "dnQualifier",
	"2.5.4.65":                   "pseudonym",
	"2.5.4.97":                   "organizationIdentifier",
	"1.2.840.113549.1.9.1":       "emailAddress",
	"1.2.840.113549.1.9.2":       "unstructuredName",
	"1.2.840.113549.1.9.8":       "unstructuredAddress",
	"0.9.2342.19200300.100.1.1":  "UID",
	"0.9.2342.19200300.100.1.25": "DC",
	"1.3.6.1.4.1.311.60.2.1.1":   "jurisdictionL",
	"1.3.6.1.4.1.311.60.2.1.2":   "jurisdictionST",
	"1.3.6.1.4.1.311.60.2.1.3":   "jurisdictionC",
}

func peX509AttributeName(oid asn1.ObjectIdentifier) string {
	s := oid.String()
	if name, ok := peX509ShortNames[s]; ok {
		return name
	}
	return s
}

var peDigestAlgorithms = map[string]string{
	"1.2.840.113549.2.2":     "md2",
	"1.2.840.113549.2.4":     "md4",
	"1.2.840.113549.2.5":     "md5",
	"1.3.14.3.2.26":          "sha1",
	"2.16.840.1.101.3.4.2.4": "sha224",
	"2.16.840.1.101.3.4.2.1": "sha256",
	"2.16.840.1.101.3.4.2.2": "sha384",
	"2.16.840.1.101.3.4.2.3": "sha512",
}

func peDigestAlgorithmName(oid asn1.ObjectIdentifier) string {
	if name, ok := peDigestAlgorithms[oid.String()]; ok {
		return name
	}
	return "undefined"
}

var peSignatureAlgorithms = map[string]string{
	"1.2.840.113549.1.1.2":   "md2WithRSAEncryption",
	"1.2.840.113549.1.1.4":   "md5WithRSAEncryption",
	"1.2.840.113549.1.1.5":   "sha1WithRSAEncryption",
	"1.2.840.113549.1.1.14":  "sha224WithRSAEncryption",
	"1.2.840.113549.1.1.11":  "sha256WithRSAEncryption",
	"1.2.840.113549.1.1.12":  "sha384WithRSAEncryption",
	"1.2.840.113549.1.1.13":  "sha512WithRSAEncryption",
	"1.2.840.113549.1.1.10":  "rsassaPss",
	"1.3.14.3.2.29":          "sha1WithRSA",
	"1.2.840.10045.4.1":      "ecdsa-with-SHA1",
	"1.2.840.10045.4.3.1":    "ecdsa-with-SHA224",
	"1.2.840.10045.4.3.2":    "ecdsa-with-SHA256",
	"1.2.840.10045.4.3.3":    "ecdsa-with-SHA384",
	"1.2.840.10045.4.3.4":    "ecdsa-with-SHA512",
	"1.2.840.10040.4.3":      "dsaWithSHA1",
	"2.16.840.1.101.3.4.3.1": "dsa_with_SHA224",
	"2.16.840.1.101.3.4.3.2": "dsa_with_SHA256",
	"1.3.101.112":            "ED25519",
	"1.3.101.113":            "ED448",
}

func peSignatureAlgorithmName(oid asn1.ObjectIdentifier) string {
	if name, ok := peSignatureAlgorithms[oid.String()]; ok {
		return name
	}
	return "undefined"
}
