package pefixture

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/md5" // #nosec G501 -- Test fixture generates legacy MD5 Authenticode signatures.
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505 -- Test fixture generates legacy SHA-1 Authenticode signatures.
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"hash"
	"math/big"
	"time"

	pe "github.com/cawalch/go-pe"
)

// SignedAuthenticodeOptions configures cryptographically valid (or
// intentionally faulted) Authenticode signatures for verification tests.
type SignedAuthenticodeOptions struct {
	UseRSA                  bool
	UseEd25519              bool
	UseRSAPSS               bool
	ImageDigestAlg          crypto.Hash
	CMSDigestAlg            crypto.Hash
	OverrideImageDigestOID  asn1.ObjectIdentifier
	OverrideSigOID          asn1.ObjectIdentifier
	NotBefore               time.Time
	NotAfter                time.Time
	OmitSignerCert          bool
	UseSubjectKeyID         bool
	CorruptSignature        bool
	CorruptSignedDigest     bool
	DuplicateMessageDigest  bool
	DuplicateSigningTime    bool
	OmitSignedAttrs         bool
	SigningTime             time.Time
	PKCS9At                 time.Time
	RFC3161At               time.Time
	CorruptTimestampImprint bool
	CorruptTimestampSig     bool
	NestedBlobs             [][]byte
}

// SignedAuthenticodePE builds a cryptographically verifiable PE32 or PE32+
// image from base (or a fresh aligned PE via [New]) and returns the signed PE
// bytes alongside the embedded leaf signer certificate.
func SignedAuthenticodePE(is64 bool, base []byte, opts SignedAuthenticodeOptions) ([]byte, *x509.Certificate) {
	if base == nil {
		base = New(is64)
	}
	aligned := append([]byte(nil), base...)
	for len(aligned)%8 != 0 {
		aligned = append(aligned, 0)
	}
	f, err := pe.New(aligned)
	if err != nil {
		panic(err)
	}
	alg := opts.ImageDigestAlg
	if alg == 0 {
		alg = crypto.SHA256
	}
	digest, err := f.AuthenticodeDigest(aligned, alg)
	if err != nil {
		panic(err)
	}
	blob, cert := VerifiedAuthenticodeBlob(digest, opts)
	return WithCertificates(aligned, CertificateRecord{
		Revision: 0x0200,
		Type:     2,
		Payload:  blob,
	}), cert
}

// VerifiedAuthenticodeBlob constructs a DER PKCS#7 SignedData blob over an
// Authenticode image digest according to opts.
func VerifiedAuthenticodeBlob(imageDigest []byte, opts SignedAuthenticodeOptions) ([]byte, *x509.Certificate) {
	imgAlg := opts.ImageDigestAlg
	if imgAlg == 0 {
		imgAlg = crypto.SHA256
	}
	cmsAlg := opts.CMSDigestAlg
	if cmsAlg == 0 {
		cmsAlg = imgAlg
	}

	key := generateTestSignerKey(opts.UseRSA, opts.UseEd25519)
	notBefore := opts.NotBefore
	if notBefore.IsZero() {
		notBefore = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	notAfter := opts.NotAfter
	if notAfter.IsZero() {
		notAfter = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	}

	caKey := generateTestSignerKey(opts.UseRSA, opts.UseEd25519)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Code Signing CA"},
		NotBefore:             time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{1, 2, 3, 4},
	}
	caCert := createCert(verifiedCertParams{tmpl: caTmpl, parent: caTmpl, pub: caKey.Public(), signer: caKey})

	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0x1001),
		Subject:      pkix.Name{CommonName: "Test Authenticode Signer"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		SubjectKeyId: []byte{5, 6, 7, 8},
	}
	leafCert := createCert(verifiedCertParams{tmpl: leafTmpl, parent: caCert, pub: key.Public(), signer: caKey})

	tsaKey := generateTestSignerKey(opts.UseRSA, opts.UseEd25519)
	tsaTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0x2001),
		Subject:      pkix.Name{CommonName: "Test TSA"},
		NotBefore:    time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2032, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		SubjectKeyId: []byte{9, 10, 11, 12},
	}
	tsaCert := createCert(verifiedCertParams{tmpl: tsaTmpl, parent: caCert, pub: tsaKey.Public(), signer: caKey})

	imgAlgOID := verifyDigestOID(imgAlg)
	if len(opts.OverrideImageDigestOID) > 0 {
		imgAlgOID = opts.OverrideImageDigestOID
	}

	var indirect authSpcIndirectData
	indirect.Data.Type = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 15}
	indirect.MessageDigest.DigestAlgorithm = pkix.AlgorithmIdentifier{Algorithm: imgAlgOID}
	indirect.MessageDigest.Digest = append([]byte(nil), imageDigest...)
	indirectDER, err := asn1.Marshal(indirect)
	if err != nil {
		panic(err)
	}

	var indirectRV asn1.RawValue
	if _, err := asn1.Unmarshal(indirectDER, &indirectRV); err != nil {
		panic(err)
	}
	contentDigest := verifyHashBytes(cmsAlg, indirectRV.Bytes)
	if opts.CorruptSignedDigest && len(contentDigest) > 0 {
		contentDigest[0] ^= 0xff
	}

	siBytes := buildVerifiedSignerInfo(verifiedSignerParams{
		cert:                    leafCert,
		key:                     key,
		contentType:             asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 4},
		contentDigest:           contentDigest,
		rawContentFallback:      indirectRV.Bytes,
		digestAlg:               cmsAlg,
		useRSAPSS:               opts.UseRSAPSS,
		overrideSigOID:          opts.OverrideSigOID,
		useSubjectKeyID:         opts.UseSubjectKeyID,
		signingTime:             opts.SigningTime,
		corruptSignature:        opts.CorruptSignature,
		duplicateMessageDigest:  opts.DuplicateMessageDigest,
		duplicateSigningTime:    opts.DuplicateSigningTime,
		omitSignedAttrs:         opts.OmitSignedAttrs,
		pkcs9At:                 opts.PKCS9At,
		rfc3161At:               opts.RFC3161At,
		tsaCert:                 tsaCert,
		tsaKey:                  tsaKey,
		corruptTimestampImprint: opts.CorruptTimestampImprint,
		corruptTimestampSig:     opts.CorruptTimestampSig,
		nestedBlobs:             opts.NestedBlobs,
	})

	var certBytes []byte
	if !opts.OmitSignerCert {
		certBytes = append(certBytes, leafCert.Raw...)
	}
	certBytes = append(certBytes, caCert.Raw...)
	if !opts.PKCS9At.IsZero() {
		certBytes = append(certBytes, tsaCert.Raw...)
	}

	sd := authSignedData{
		Version:          1,
		DigestAlgorithms: []pkix.AlgorithmIdentifier{{Algorithm: verifyDigestOID(cmsAlg)}},
		EncapContentInfo: authContentInfo{
			ContentType: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 4},
			Content: asn1.RawValue{
				Class:      asn1.ClassContextSpecific,
				Tag:        0,
				IsCompound: true,
				Bytes:      indirectDER,
			},
		},
		Certificates: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      certBytes,
		},
		SignerInfos: asn1.RawValue{
			Class:      asn1.ClassUniversal,
			Tag:        asn1.TagSet,
			IsCompound: true,
			Bytes:      siBytes,
		},
	}
	sdDER, err := asn1.Marshal(sd)
	if err != nil {
		panic(err)
	}
	ciDER, err := asn1.Marshal(authContentInfo{
		ContentType: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2},
		Content: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      sdDER,
		},
	})
	if err != nil {
		panic(err)
	}
	return ciDER, leafCert
}

type verifiedSignerParams struct {
	cert                    *x509.Certificate
	key                     crypto.Signer
	contentType             asn1.ObjectIdentifier
	contentDigest           []byte
	rawContentFallback      []byte
	digestAlg               crypto.Hash
	useRSAPSS               bool
	overrideSigOID          asn1.ObjectIdentifier
	useSubjectKeyID         bool
	signingTime             time.Time
	corruptSignature        bool
	duplicateMessageDigest  bool
	duplicateSigningTime    bool
	omitSignedAttrs         bool
	omitContentType         bool
	pkcs9At                 time.Time
	rfc3161At               time.Time
	tsaCert                 *x509.Certificate
	tsaKey                  crypto.Signer
	corruptTimestampImprint bool
	corruptTimestampSig     bool
	nestedBlobs             [][]byte
}

func appendAuthAttr(dst *[]byte, oid asn1.ObjectIdentifier, valDER []byte) {
	var rv asn1.RawValue
	if _, err := asn1.Unmarshal(valDER, &rv); err != nil {
		panic(err)
	}
	b, err := asn1.Marshal(authAttribute{Type: oid, Values: []asn1.RawValue{rv}})
	if err != nil {
		panic(err)
	}
	*dst = append(*dst, b...)
}

func buildVerifiedSignedAttrs(p verifiedSignerParams) (authAttrs, toSign []byte) {
	oidContentType := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidSigningTime := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}

	if !p.omitContentType {
		ctDER, _ := asn1.Marshal(p.contentType)
		appendAuthAttr(&authAttrs, oidContentType, ctDER)
	}
	mdDER, _ := asn1.Marshal(p.contentDigest)
	appendAuthAttr(&authAttrs, oidMessageDigest, mdDER)
	if p.duplicateMessageDigest {
		appendAuthAttr(&authAttrs, oidMessageDigest, mdDER)
	}
	if !p.signingTime.IsZero() {
		tDER, _ := asn1.Marshal(p.signingTime.UTC())
		appendAuthAttr(&authAttrs, oidSigningTime, tDER)
		if p.duplicateSigningTime {
			t2DER, _ := asn1.Marshal(p.signingTime.Add(time.Minute).UTC())
			appendAuthAttr(&authAttrs, oidSigningTime, t2DER)
		}
	}
	var err error
	toSign, err = asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSet,
		IsCompound: true,
		Bytes:      authAttrs,
	})
	if err != nil {
		panic(err)
	}
	return authAttrs, toSign
}

func buildVerifiedSignerInfo(p verifiedSignerParams) []byte {
	oidCountersig := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 6}
	oidAuthTS := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 3, 3, 1}
	oidNested := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 4, 1}

	var authAttrs []byte
	toSign := p.rawContentFallback
	if !p.omitSignedAttrs {
		authAttrs, toSign = buildVerifiedSignedAttrs(p)
	}

	sigAlgID, sigBytes := signVerifiedBytes(verifiedSignRequest{
		key:         p.key,
		alg:         p.digestAlg,
		usePSS:      p.useRSAPSS,
		overrideOID: p.overrideSigOID,
		payload:     toSign,
	})
	if p.corruptSignature && len(sigBytes) > 0 {
		sigBytes[len(sigBytes)/2] ^= 0x55
	}

	version := 1
	var sidVal asn1.RawValue
	if p.useSubjectKeyID {
		version = 3
		raw, _ := asn1.Marshal(asn1.RawValue{
			Class: asn1.ClassContextSpecific,
			Tag:   0,
			Bytes: p.cert.SubjectKeyId,
		})
		_, _ = asn1.Unmarshal(raw, &sidVal)
	} else {
		sidDER, err := asn1.Marshal(authIssuerAndSerial{
			Issuer: asn1.RawValue{FullBytes: p.cert.RawIssuer},
			Serial: p.cert.SerialNumber,
		})
		if err != nil {
			panic(err)
		}
		_, _ = asn1.Unmarshal(sidDER, &sidVal)
	}

	var unauthAttrs []byte
	if !p.pkcs9At.IsZero() {
		imprintTarget := append([]byte(nil), sigBytes...)
		if p.corruptTimestampImprint && len(imprintTarget) > 0 {
			imprintTarget[0] ^= 0x11
		}
		csSI := buildVerifiedSignerInfo(verifiedSignerParams{
			cert:             p.tsaCert,
			key:              p.tsaKey,
			contentDigest:    verifyHashBytes(p.digestAlg, imprintTarget),
			digestAlg:        p.digestAlg,
			omitContentType:  true,
			signingTime:      p.pkcs9At,
			corruptSignature: p.corruptTimestampSig,
		})
		appendAuthAttr(&unauthAttrs, oidCountersig, csSI)
	}
	if !p.rfc3161At.IsZero() {
		tsBlob := buildVerifiedRFC3161(p, sigBytes)
		appendAuthAttr(&unauthAttrs, oidAuthTS, tsBlob)
	}
	for _, nb := range p.nestedBlobs {
		appendAuthAttr(&unauthAttrs, oidNested, nb)
	}

	si := authSignerInfo{
		Version:            version,
		SID:                sidVal,
		DigestAlgorithm:    pkix.AlgorithmIdentifier{Algorithm: verifyDigestOID(p.digestAlg)},
		SignatureAlgorithm: sigAlgID,
		Signature:          sigBytes,
	}
	if !p.omitSignedAttrs {
		si.SignedAttrs = asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      authAttrs,
		}
	}
	if len(unauthAttrs) > 0 {
		si.UnsignedAttrs = asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        1,
			IsCompound: true,
			Bytes:      unauthAttrs,
		}
	}
	siDER, err := asn1.Marshal(si)
	if err != nil {
		panic(err)
	}
	return siDER
}

func buildVerifiedRFC3161(p verifiedSignerParams, sig []byte) []byte {
	target := append([]byte(nil), sig...)
	if p.corruptTimestampImprint && len(target) > 0 {
		target[0] ^= 0xaa
	}
	digest := sha256.Sum256(target)
	tst := authTSTInfo{
		Version:      1,
		Policy:       asn1.ObjectIdentifier{1, 2, 3, 4},
		SerialNumber: big.NewInt(99),
		GenTime:      p.rfc3161At.UTC().Truncate(time.Second),
	}
	tst.MessageImprint.HashAlgorithm = pkix.AlgorithmIdentifier{Algorithm: verifyDigestOID(crypto.SHA256)}
	tst.MessageImprint.HashedMessage = digest[:]
	tstDER, err := asn1.Marshal(tst)
	if err != nil {
		panic(err)
	}
	octDER, _ := asn1.Marshal(tstDER)
	tstDigest := sha256.Sum256(tstDER)

	siDER := buildVerifiedSignerInfo(verifiedSignerParams{
		cert:             p.tsaCert,
		key:              p.tsaKey,
		contentType:      asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4},
		contentDigest:    tstDigest[:],
		digestAlg:        crypto.SHA256,
		corruptSignature: p.corruptTimestampSig,
	})
	sd := authSignedData{
		Version:          3,
		DigestAlgorithms: []pkix.AlgorithmIdentifier{{Algorithm: verifyDigestOID(crypto.SHA256)}},
		EncapContentInfo: authContentInfo{
			ContentType: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4},
			Content: asn1.RawValue{
				Class:      asn1.ClassContextSpecific,
				Tag:        0,
				IsCompound: true,
				Bytes:      octDER,
			},
		},
		Certificates: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      p.tsaCert.Raw,
		},
		SignerInfos: asn1.RawValue{
			Class:      asn1.ClassUniversal,
			Tag:        asn1.TagSet,
			IsCompound: true,
			Bytes:      siDER,
		},
	}
	sdDER, err := asn1.Marshal(sd)
	if err != nil {
		panic(err)
	}
	ciDER, err := asn1.Marshal(authContentInfo{
		ContentType: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2},
		Content: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      sdDER,
		},
	})
	if err != nil {
		panic(err)
	}
	return ciDER
}

func generateTestSignerKey(useRSA, useEd25519 bool) crypto.Signer {
	if useRSA {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		return k
	}
	if useEd25519 {
		_, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
		return k
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return k
}

type verifiedCertParams struct {
	tmpl   *x509.Certificate
	parent *x509.Certificate
	pub    crypto.PublicKey
	signer crypto.Signer
}

func createCert(p verifiedCertParams) *x509.Certificate {
	der, err := x509.CreateCertificate(rand.Reader, p.tmpl, p.parent, p.pub, p.signer)
	if err != nil {
		panic(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return cert
}

type verifiedSignRequest struct {
	key         crypto.Signer
	alg         crypto.Hash
	usePSS      bool
	overrideOID asn1.ObjectIdentifier
	payload     []byte
}

func signVerifiedBytes(req verifiedSignRequest) (pkix.AlgorithmIdentifier, []byte) {
	digest := verifyHashBytes(req.alg, req.payload)
	switch k := req.key.(type) {
	case *rsa.PrivateKey:
		if req.usePSS {
			opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: req.alg}
			sig, err := rsa.SignPSS(rand.Reader, k, req.alg, digest, opts)
			if err != nil {
				panic(err)
			}
			type pssParams struct {
				HashAlgorithm    pkix.AlgorithmIdentifier `asn1:"explicit,tag:0"`
				MaskGenAlgorithm pkix.AlgorithmIdentifier `asn1:"explicit,tag:1"`
				SaltLength       int                      `asn1:"explicit,tag:2"`
				TrailerField     int                      `asn1:"explicit,tag:3"`
			}
			mgfParam, _ := asn1.Marshal(pkix.AlgorithmIdentifier{Algorithm: verifyDigestOID(req.alg)})
			paramsDER, _ := asn1.Marshal(pssParams{
				HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: verifyDigestOID(req.alg)},
				MaskGenAlgorithm: pkix.AlgorithmIdentifier{
					Algorithm:  asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8},
					Parameters: asn1.RawValue{FullBytes: mgfParam},
				},
				SaltLength:   req.alg.Size(),
				TrailerField: 1,
			})
			oid := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
			if len(req.overrideOID) > 0 {
				oid = req.overrideOID
			}
			return pkix.AlgorithmIdentifier{Algorithm: oid, Parameters: asn1.RawValue{FullBytes: paramsDER}}, sig
		}
		sig, err := rsa.SignPKCS1v15(rand.Reader, k, req.alg, digest)
		if err != nil {
			panic(err)
		}
		oid := rsaSigOID(req.alg)
		if len(req.overrideOID) > 0 {
			oid = req.overrideOID
		}
		return pkix.AlgorithmIdentifier{Algorithm: oid}, sig

	case *ecdsa.PrivateKey:
		sig, err := ecdsa.SignASN1(rand.Reader, k, digest)
		if err != nil {
			panic(err)
		}
		oid := ecdsaSigOID(req.alg)
		if len(req.overrideOID) > 0 {
			oid = req.overrideOID
		}
		return pkix.AlgorithmIdentifier{Algorithm: oid}, sig

	case ed25519.PrivateKey:
		sig := ed25519.Sign(k, req.payload)
		oid := asn1.ObjectIdentifier{1, 3, 101, 112}
		if len(req.overrideOID) > 0 {
			oid = req.overrideOID
		}
		return pkix.AlgorithmIdentifier{Algorithm: oid}, sig

	default:
		panic(fmt.Sprintf("unsupported key type %T", req.key))
	}
}

func verifyDigestOID(h crypto.Hash) asn1.ObjectIdentifier {
	switch h {
	case crypto.MD5:
		return asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 5}
	case crypto.SHA1:
		return asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	case crypto.SHA256:
		return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	case crypto.SHA384:
		return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	case crypto.SHA512:
		return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	default:
		panic(fmt.Sprintf("unsupported hash %v", h))
	}
}

func rsaSigOID(h crypto.Hash) asn1.ObjectIdentifier {
	switch h {
	case crypto.MD5:
		return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 4}
	case crypto.SHA1:
		return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	case crypto.SHA256:
		return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	case crypto.SHA384:
		return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	case crypto.SHA512:
		return asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	default:
		panic(fmt.Sprintf("unsupported RSA hash %v", h))
	}
}

func ecdsaSigOID(h crypto.Hash) asn1.ObjectIdentifier {
	switch h {
	case crypto.SHA1:
		return asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
	case crypto.SHA256:
		return asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	case crypto.SHA384:
		return asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	case crypto.SHA512:
		return asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	default:
		panic(fmt.Sprintf("unsupported ECDSA hash %v", h))
	}
}

func verifyHashBytes(alg crypto.Hash, b []byte) []byte {
	var h hash.Hash
	switch alg {
	case crypto.MD5:
		h = md5.New() // #nosec G401 -- Test fixture generates legacy MD5 Authenticode digests.
	case crypto.SHA1:
		h = sha1.New() // #nosec G401 -- Test fixture generates legacy SHA-1 Authenticode digests.
	case crypto.SHA256:
		h = sha256.New()
	case crypto.SHA384:
		h = sha512.New384()
	case crypto.SHA512:
		h = sha512.New()
	default:
		panic(fmt.Sprintf("unsupported hash %v", alg))
	}
	_, _ = h.Write(b)
	return h.Sum(nil)
}
