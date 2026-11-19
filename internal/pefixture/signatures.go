package pefixture

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"math/big"
	"sync"
	"time"
)

// CertificateRecord describes one raw WIN_CERTIFICATE entry attached by [WithCertificates].
type CertificateRecord struct {
	Revision uint16
	Type     uint16
	Payload  []byte
}

// WithCertificates returns a copy of peBytes with the supplied WIN_CERTIFICATE
// records appended and DataDirectory[4] (SECURITY) pointed at them.
func WithCertificates(peBytes []byte, records ...CertificateRecord) []byte {
	out := append([]byte(nil), peBytes...)
	for len(out)%8 != 0 {
		out = append(out, 0)
	}
	secOff := uint32(len(out))
	for _, rec := range records {
		rev := rec.Revision
		if rev == 0 {
			rev = 0x0200
		}
		typ := rec.Type
		if typ == 0 {
			typ = 2
		}
		hdr := make([]byte, 8)
		binary.LittleEndian.PutUint32(hdr[0:], uint32(8+len(rec.Payload)))
		binary.LittleEndian.PutUint16(hdr[4:], rev)
		binary.LittleEndian.PutUint16(hdr[6:], typ)
		out = append(out, hdr...)
		out = append(out, rec.Payload...)
		for len(out)%8 != 0 {
			out = append(out, 0)
		}
	}
	secSize := uint32(len(out)) - secOff
	magic := binary.LittleEndian.Uint16(out[0x98:])
	ddOff := 0x98 + 96 + 4*8
	if magic == 0x20b {
		ddOff = 0x98 + 112 + 4*8
	}
	binary.LittleEndian.PutUint32(out[ddOff:], secOff)
	binary.LittleEndian.PutUint32(out[ddOff+4:], secSize)
	return out
}

// AuthenticodeOptions configures synthetic DER PKCS#7 SignedData blobs built by [AuthenticodeBlob].
type AuthenticodeOptions struct {
	Subject              *pkix.Name
	Serial               *big.Int
	NotBefore            time.Time
	NotAfter             time.Time
	UseRSA               bool
	IncludeChain         bool
	DigestAlgorithmOID   asn1.ObjectIdentifier
	IndirectDigestOID    asn1.ObjectIdentifier
	IndirectDigest       []byte
	MessageDigest        []byte
	OmitSignedAttrs      bool
	OmitCertificates     bool
	OmitSignerInfos      bool
	UseSubjectKeyID      bool
	UnknownCertSigOID    asn1.ObjectIdentifier
	ProgramName          string
	PKCS9CountersignAt   time.Time
	CountersignDigest    []byte
	CountersignDigestOID asn1.ObjectIdentifier
	RFC3161TimestampAt   time.Time
	NestedBlobs          [][]byte
}

type authContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type authSignedData struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo authContentInfo
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	SignerInfos      asn1.RawValue `asn1:"set"`
}

type authSignerInfo struct {
	Version            int
	SID                asn1.RawValue
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttrs        asn1.RawValue `asn1:"optional,tag:0"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
	UnsignedAttrs      asn1.RawValue `asn1:"optional,tag:1"`
}

type authAttribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

type authIssuerAndSerial struct {
	Issuer asn1.RawValue
	Serial *big.Int
}

type authSpcIndirectData struct {
	Data struct {
		Type  asn1.ObjectIdentifier
		Value asn1.RawValue `asn1:"optional"`
	}
	MessageDigest struct {
		DigestAlgorithm pkix.AlgorithmIdentifier
		Digest          []byte
	}
}

type authTSTInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint struct {
		HashAlgorithm pkix.AlgorithmIdentifier
		HashedMessage []byte
	}
	SerialNumber *big.Int
	GenTime      time.Time `asn1:"generalized"`
}

// AuthenticodeBlob builds a synthetic DER-encoded PKCS#7 SignedData payload for
// PE signature metadata tests.
func AuthenticodeBlob(opts AuthenticodeOptions) ([]byte, *x509.Certificate) {
	oidSHA256 := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidECDSAWithSHA256 := asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidRSAWithSHA256 := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSpcIndirect := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 4}
	oidSpcPEData := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 15}

	digestOID := opts.DigestAlgorithmOID
	if len(digestOID) == 0 {
		digestOID = oidSHA256
	}
	indDigestOID := opts.IndirectDigestOID
	if len(indDigestOID) == 0 {
		indDigestOID = digestOID
	}

	subject := pkix.Name{
		Country:      []string{"US"},
		Organization: []string{"Example Corp"},
		CommonName:   "Test Code Signer",
	}
	if opts.Subject != nil {
		subject = *opts.Subject
	}
	serial := opts.Serial
	if serial == nil {
		serial = big.NewInt(0x123456)
	}
	notBefore := opts.NotBefore
	if notBefore.IsZero() {
		notBefore = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	notAfter := opts.NotAfter
	if notAfter.IsZero() {
		notAfter = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	}

	var leafDER, caDER, rootDER []byte
	var leafCert *x509.Certificate
	var sigOID asn1.ObjectIdentifier

	spec := certSetSpec{
		subject:      subject,
		serial:       serial,
		notBefore:    notBefore,
		notAfter:     notAfter,
		includeChain: opts.IncludeChain,
	}
	if opts.UseRSA {
		rsaKey := cachedTestKey(true, false, testKeyLeaf).(*rsa.PrivateKey)
		sigOID = oidRSAWithSHA256
		rootDER, caDER, leafDER, leafCert = createCertSet(rsaKey, &rsaKey.PublicKey, spec)
	} else {
		ecKey := cachedTestKey(false, false, testKeyLeaf).(*ecdsa.PrivateKey)
		sigOID = oidECDSAWithSHA256
		rootDER, caDER, leafDER, leafCert = createCertSet(ecKey, &ecKey.PublicKey, spec)
	}

	if len(opts.UnknownCertSigOID) > 0 {
		var raw struct {
			TBS struct {
				Raw        asn1.RawContent
				Version    int `asn1:"optional,explicit,tag:0,default:0"`
				Serial     *big.Int
				SigAlg     pkix.AlgorithmIdentifier
				Issuer     asn1.RawValue
				Validity   asn1.RawValue
				Subject    asn1.RawValue
				PubKeyInfo asn1.RawValue
				Extensions asn1.RawValue `asn1:"optional,explicit,tag:3"`
			}
			Alg pkix.AlgorithmIdentifier
			Sig asn1.BitString
		}
		if _, err := asn1.Unmarshal(leafDER, &raw); err != nil {
			panic(err)
		}
		alg := pkix.AlgorithmIdentifier{Algorithm: opts.UnknownCertSigOID}
		raw.TBS.Raw = nil
		raw.TBS.SigAlg = alg
		raw.Alg = alg
		leafDER, _ = asn1.Marshal(raw)
	}

	indDigest := opts.IndirectDigest
	if len(indDigest) == 0 {
		sum := sha256.Sum256([]byte("synthetic-pe-image"))
		indDigest = sum[:]
	}
	ind := authSpcIndirectData{}
	ind.Data.Type = oidSpcPEData
	ind.MessageDigest.DigestAlgorithm = pkix.AlgorithmIdentifier{Algorithm: indDigestOID}
	ind.MessageDigest.Digest = indDigest
	indDER, _ := asn1.Marshal(ind)

	var certsBytes []byte
	if !opts.OmitCertificates {
		// Emit root -> intermediate -> leaf order to test leaf-to-root chain building.
		certsBytes = append(certsBytes, rootDER...)
		certsBytes = append(certsBytes, caDER...)
		certsBytes = append(certsBytes, leafDER...)
	}

	var signerInfosBytes []byte
	if !opts.OmitSignerInfos {
		signerInfosBytes = buildAuthSignerInfo(signerInfoSpec{
			leafCert:  leafCert,
			digestOID: digestOID,
			sigOID:    sigOID,
			opts:      opts,
		}, &certsBytes)
	}

	return wrapSignedData(signedDataSpec{
		version:     1,
		digestOID:   digestOID,
		contentType: oidSpcIndirect,
		contentDER:  indDER,
		certsBytes:  certsBytes,
		signerInfos: signerInfosBytes,
	}), leafCert
}

type certSetSpec struct {
	subject      pkix.Name
	serial       *big.Int
	notBefore    time.Time
	notAfter     time.Time
	includeChain bool
}

type signerInfoSpec struct {
	leafCert  *x509.Certificate
	digestOID asn1.ObjectIdentifier
	sigOID    asn1.ObjectIdentifier
	opts      AuthenticodeOptions
}

func mustIssuerAndSerialSID(cert *x509.Certificate) asn1.RawValue {
	var issuerRaw asn1.RawValue
	if _, err := asn1.Unmarshal(cert.RawIssuer, &issuerRaw); err != nil {
		panic(err)
	}
	sidDER, err := asn1.Marshal(authIssuerAndSerial{Issuer: issuerRaw, Serial: cert.SerialNumber})
	if err != nil {
		panic(err)
	}
	return asn1.RawValue{FullBytes: sidDER}
}

func createCertSet(signer any, pub any, spec certSetSpec) (rootDER, caDER, leafDER []byte, leafCert *x509.Certificate) {
	leafTmpl := &x509.Certificate{
		SerialNumber: spec.serial,
		Subject:      spec.subject,
		NotBefore:    spec.notBefore,
		NotAfter:     spec.notAfter,
		SubjectKeyId: []byte{0x10, 0x20, 0x30, 0x40},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	if !spec.includeChain {
		var err error
		leafDER, err = x509.CreateCertificate(rand.Reader, leafTmpl, leafTmpl, pub, signer)
		if err != nil {
			panic(err)
		}
		leafCert, err = x509.ParseCertificate(leafDER)
		if err != nil {
			panic(err)
		}
		return nil, nil, leafDER, leafCert
	}

	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Country: []string{"US"}, Organization: []string{"Example Root"}, CommonName: "Example Root CA"},
		NotBefore:             time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	var err error
	rootDER, err = x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, pub, signer)
	if err != nil {
		panic(err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		panic(err)
	}

	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{Country: []string{"US"}, Organization: []string{"Example Inter"}, CommonName: "Example Intermediate CA"},
		NotBefore:             time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err = x509.CreateCertificate(rand.Reader, caTmpl, rootCert, pub, signer)
	if err != nil {
		panic(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		panic(err)
	}

	leafDER, err = x509.CreateCertificate(rand.Reader, leafTmpl, caCert, pub, signer)
	if err != nil {
		panic(err)
	}
	leafCert, err = x509.ParseCertificate(leafDER)
	if err != nil {
		panic(err)
	}
	return rootDER, caDER, leafDER, leafCert
}

func buildAuthSignerInfo(spec signerInfoSpec, outerCertsBytes *[]byte) []byte {
	leafCert := spec.leafCert
	digestOID := spec.digestOID
	sigOID := spec.sigOID
	opts := spec.opts

	oidContentType := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidSigningTime := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	oidCountersig := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 6}
	oidOpusInfo := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 12}
	oidNested := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 4, 1}
	oidAuthTS := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 3, 3, 1}
	oidTSTInfo := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	oidSpcIndirect := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 4}

	var sid asn1.RawValue
	version := 1
	if opts.UseSubjectKeyID {
		version = 3
		sid = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: leafCert.SubjectKeyId}
	} else {
		sid = mustIssuerAndSerialSID(leafCert)
	}

	var authAttrs []byte
	if !opts.OmitSignedAttrs {
		ct, _ := asn1.Marshal(oidSpcIndirect)
		authAttrs = append(authAttrs, authAttr(oidContentType, ct)...)
		md := opts.MessageDigest
		if len(md) == 0 {
			sum := sha256.Sum256([]byte("signer-message-digest"))
			md = sum[:]
		}
		mdDER, _ := asn1.Marshal(md)
		authAttrs = append(authAttrs, authAttr(oidMessageDigest, mdDER)...)
		if opts.ProgramName != "" {
			opus := struct {
				ProgramName struct {
					ASCII string `asn1:"optional,tag:1,ia5"`
				} `asn1:"optional,tag:0"`
			}{}
			opus.ProgramName.ASCII = opts.ProgramName
			opDER, _ := asn1.Marshal(opus)
			authAttrs = append(authAttrs, authAttr(oidOpusInfo, opDER)...)
		}
	}

	var unauthAttrs []byte
	for _, nested := range opts.NestedBlobs {
		unauthAttrs = append(unauthAttrs, authAttr(oidNested, nested)...)
	}

	if !opts.PKCS9CountersignAt.IsZero() {
		tsKey := cachedTestKey(false, false, testKeyTSA).(*ecdsa.PrivateKey)
		tsTmpl := &x509.Certificate{
			SerialNumber: big.NewInt(0x7a),
			Subject:      pkix.Name{CommonName: "PKCS9 Timestamp Authority"},
			NotBefore:    time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			NotAfter:     time.Date(2032, 1, 1, 0, 0, 0, 0, time.UTC),
		}
		tsDER, _ := x509.CreateCertificate(rand.Reader, tsTmpl, tsTmpl, &tsKey.PublicKey, tsKey)
		tsCert, _ := x509.ParseCertificate(tsDER)
		if !opts.OmitCertificates {
			*outerCertsBytes = append(*outerCertsBytes, tsDER...)
		}
		tsSID := mustIssuerAndSerialSID(tsCert)
		tsTimeDER, _ := asn1.Marshal(opts.PKCS9CountersignAt.UTC())
		tsAuth := authAttr(oidSigningTime, tsTimeDER)
		if len(opts.CountersignDigest) > 0 {
			mdDER, _ := asn1.Marshal(opts.CountersignDigest)
			tsAuth = append(tsAuth, authAttr(oidMessageDigest, mdDER)...)
		}
		csAlgOID := opts.CountersignDigestOID
		if len(csAlgOID) == 0 {
			csAlgOID = digestOID
		}
		tsSI := authSignerInfo{
			Version:            1,
			SID:                tsSID,
			DigestAlgorithm:    pkix.AlgorithmIdentifier{Algorithm: csAlgOID},
			SignedAttrs:        authTag0(tsAuth),
			SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: sigOID},
			Signature:          []byte{1, 2, 3},
		}
		tsSIDER, _ := asn1.Marshal(tsSI)
		unauthAttrs = append(unauthAttrs, authAttr(oidCountersig, tsSIDER)...)
	}

	if !opts.RFC3161TimestampAt.IsZero() {
		tsKey := cachedTestKey(false, false, testKeyTSA).(*ecdsa.PrivateKey)
		tsTmpl := &x509.Certificate{
			SerialNumber: big.NewInt(0x7b),
			Subject:      pkix.Name{CommonName: "RFC3161 TSA"},
			NotBefore:    time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			NotAfter:     time.Date(2032, 1, 1, 0, 0, 0, 0, time.UTC),
		}
		tsDER, _ := x509.CreateCertificate(rand.Reader, tsTmpl, tsTmpl, &tsKey.PublicKey, tsKey)
		tsCert, _ := x509.ParseCertificate(tsDER)
		tsSID := mustIssuerAndSerialSID(tsCert)
		imprint := opts.CountersignDigest
		if len(imprint) == 0 {
			imprint = make([]byte, 32)
		}
		_, tstOct := buildTSTInfoDER(tstInfoSpec{
			hashOID: digestOID,
			imprint: imprint,
			serial:  88,
			genTime: opts.RFC3161TimestampAt.UTC(),
		})
		tsSI := authSignerInfo{
			Version:            1,
			SID:                tsSID,
			DigestAlgorithm:    pkix.AlgorithmIdentifier{Algorithm: digestOID},
			SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: sigOID},
			Signature:          []byte{4, 5, 6},
		}
		tsSIDER, _ := asn1.Marshal(tsSI)
		tsCIDER := wrapSignedData(signedDataSpec{
			version:     3,
			digestOID:   digestOID,
			contentType: oidTSTInfo,
			contentDER:  tstOct,
			certsBytes:  tsDER,
			signerInfos: tsSIDER,
		})
		unauthAttrs = append(unauthAttrs, authAttr(oidAuthTS, tsCIDER)...)
	}

	si := authSignerInfo{
		Version:            version,
		SID:                sid,
		DigestAlgorithm:    pkix.AlgorithmIdentifier{Algorithm: digestOID},
		SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: sigOID},
		Signature:          []byte{9, 8, 7, 6},
	}
	if len(authAttrs) > 0 {
		si.SignedAttrs = authTag0(authAttrs)
	}
	if len(unauthAttrs) > 0 {
		si.UnsignedAttrs = authTag1(unauthAttrs)
	}
	siDER, _ := asn1.Marshal(si)
	return siDER
}

type testKeyRole uint8

const (
	testKeyLeaf testKeyRole = iota
	testKeyCA
	testKeyTSA
)

var (
	cachedRSAKeys = [3]func() *rsa.PrivateKey{
		sync.OnceValue(mustGenRSA),
		sync.OnceValue(mustGenRSA),
		sync.OnceValue(mustGenRSA),
	}
	cachedECKeys = [3]func() *ecdsa.PrivateKey{
		sync.OnceValue(mustGenEC),
		sync.OnceValue(mustGenEC),
		sync.OnceValue(mustGenEC),
	}
	cachedEdKeys = [3]func() ed25519.PrivateKey{
		sync.OnceValue(mustGenEd),
		sync.OnceValue(mustGenEd),
		sync.OnceValue(mustGenEd),
	}
)

func mustGenRSA() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
}

func mustGenEC() *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return k
}

func mustGenEd() ed25519.PrivateKey {
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return k
}

func cachedTestKey(useRSA, useEd25519 bool, role testKeyRole) crypto.Signer {
	if useRSA {
		return cachedRSAKeys[role]()
	}
	if useEd25519 {
		return cachedEdKeys[role]()
	}
	return cachedECKeys[role]()
}

type signedDataSpec struct {
	version     int
	digestOID   asn1.ObjectIdentifier
	contentType asn1.ObjectIdentifier
	contentDER  []byte
	certsBytes  []byte
	signerInfos []byte
}

func wrapSignedData(spec signedDataSpec) []byte {
	sd := authSignedData{
		Version:          spec.version,
		DigestAlgorithms: []pkix.AlgorithmIdentifier{{Algorithm: spec.digestOID}},
		EncapContentInfo: authContentInfo{
			ContentType: spec.contentType,
			Content:     authTag0(spec.contentDER),
		},
		SignerInfos: asn1.RawValue{
			Class:      asn1.ClassUniversal,
			Tag:        asn1.TagSet,
			IsCompound: true,
			Bytes:      spec.signerInfos,
		},
	}
	if len(spec.certsBytes) > 0 {
		sd.Certificates = authTag0(spec.certsBytes)
	}
	sdDER, err := asn1.Marshal(sd)
	if err != nil {
		panic(err)
	}
	ciDER, err := asn1.Marshal(authContentInfo{
		ContentType: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2},
		Content:     authTag0(sdDER),
	})
	if err != nil {
		panic(err)
	}
	return ciDER
}

type tstInfoSpec struct {
	hashOID asn1.ObjectIdentifier
	imprint []byte
	serial  int64
	genTime time.Time
}

func buildTSTInfoDER(spec tstInfoSpec) (tstDER, octDER []byte) {
	tst := authTSTInfo{
		Version:      1,
		Policy:       asn1.ObjectIdentifier{1, 2, 3, 4},
		SerialNumber: big.NewInt(spec.serial),
		GenTime:      spec.genTime,
	}
	tst.MessageImprint.HashAlgorithm = pkix.AlgorithmIdentifier{Algorithm: spec.hashOID}
	tst.MessageImprint.HashedMessage = spec.imprint
	var err error
	tstDER, err = asn1.Marshal(tst)
	if err != nil {
		panic(err)
	}
	octDER, err = asn1.Marshal(tstDER)
	if err != nil {
		panic(err)
	}
	return tstDER, octDER
}

func authTag0(der []byte) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: der}
}

func authTag1(der []byte) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, IsCompound: true, Bytes: der}
}

func appendAuthAttr(dst *[]byte, oid asn1.ObjectIdentifier, valDER []byte) {
	*dst = append(*dst, authAttr(oid, valDER)...)
}

func authAttr(oid asn1.ObjectIdentifier, valDER []byte) []byte {
	var rv asn1.RawValue
	if _, err := asn1.Unmarshal(valDER, &rv); err != nil {
		panic(err)
	}
	b, err := asn1.Marshal(authAttribute{Type: oid, Values: []asn1.RawValue{rv}})
	if err != nil {
		panic(err)
	}
	return b
}
