package integration

import (
	"bytes"
	"crypto/sha1"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/cawalch/go-yara/internal/pefixture"
)

func TestLibyaraPESignatures(t *testing.T) {
	libyaraOracle(t)

	sigTime := time.Date(2026, 5, 2, 10, 0, 0, 0, time.UTC)
	tsaTime := time.Date(2026, 5, 3, 11, 0, 0, 0, time.UTC)

	nestedBlob, nestedCert := pefixture.AuthenticodeBlob(pefixture.AuthenticodeOptions{
		Subject:     &pkix.Name{CommonName: "Nested Signer"},
		Serial:      big.NewInt(0x7777),
		UseRSA:      true,
		ProgramName: "NestedApp",
	})
	nestedThumb := sha1.Sum(nestedCert.Raw)

	primaryBlob, primaryCert := pefixture.AuthenticodeBlob(pefixture.AuthenticodeOptions{
		Subject: &pkix.Name{
			Country:            []string{"US"},
			Province:           []string{"California"},
			Locality:           []string{"Mountain View"},
			Organization:       []string{"Example Corp, Inc."},
			OrganizationalUnit: []string{"Security/Ops", "Team=Alpha"},
			CommonName:         "Primary / ÜTF8",
			ExtraNames: []pkix.AttributeTypeAndValue{
				{Type: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}, Value: "sec@example.invalid"},
				{Type: asn1.ObjectIdentifier{1, 2, 3, 4, 5}, Value: "ext"},
			},
		},
		Serial:             new(big.Int).SetBytes([]byte{0x80, 0xab, 0xcd}),
		NotBefore:          time.Date(1960, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:           time.Date(2060, 1, 1, 0, 0, 0, 0, time.UTC),
		IncludeChain:       true,
		IndirectDigest:     bytes.Repeat([]byte{0x11}, 20),
		IndirectDigestOID:  asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26},
		MessageDigest:      bytes.Repeat([]byte{0x22}, 32),
		ProgramName:        "PrimaryApp",
		PKCS9CountersignAt: sigTime,
		CountersignDigest:  bytes.Repeat([]byte{0x33}, 32),
		RFC3161TimestampAt: tsaTime,
		NestedBlobs:        [][]byte{nestedBlob},
	})
	primaryThumb := sha1.Sum(primaryCert.Raw)

	zeroSerialBlob, _ := pefixture.AuthenticodeBlob(pefixture.AuthenticodeOptions{
		Serial:          big.NewInt(0),
		OmitSignedAttrs: true,
	})
	emptySignerBlob, _ := pefixture.AuthenticodeBlob(pefixture.AuthenticodeOptions{
		OmitSignerInfos: true,
	})

	predicates := []string{
		`defined pe.number_of_signatures`,
		`pe.number_of_signatures == 0`,
		`pe.number_of_signatures == 1`,
		`pe.number_of_signatures == 2`,
		`defined pe.signatures[0].serial`,
		`defined pe.signatures[1].serial`,
		`defined pe.signatures[2].serial`,
		`defined pe.signatures[-1].serial`,
		`pe.signatures[0].serial == "00:80:ab:cd"`,
		`pe.signatures[0].serial == "00"`,
		`pe.signatures[0].version == 3`,
		`pe.signatures[0].algorithm == "ecdsa-with-SHA256"`,
		`pe.signatures[0].algorithm_oid == "1.2.840.10045.4.3.2"`,
		fmt.Sprintf(`pe.signatures[0].thumbprint == "%s"`, hex.EncodeToString(primaryThumb[:])),
		`pe.signatures[0].issuer == "/C=US/O=Example Inter/CN=Example Intermediate CA"`,
		`pe.signatures[0].subject == "/C=US/ST=California/L=Mountain View/O=Example Corp, Inc./OU=Team=Alpha+OU=Security/Ops/CN=Primary / \\xC3\\x9CTF8/emailAddress=sec@example.invalid/1.2.3.4.5=ext"`,
		`pe.signatures[0].not_before == -315619200`,
		`pe.signatures[0].not_after == 2840140800`,
		fmt.Sprintf(`pe.signatures[0].digest == "%s"`, hex.EncodeToString(bytes.Repeat([]byte{0x11}, 20))),
		`pe.signatures[0].digest_alg == "sha1"`,
		`pe.signatures[0].number_of_certificates == 5`,
		`pe.signatures[0].number_of_certificates == 1`,
		`pe.signatures[0].certificates[0].subject == "/C=US/O=Example Root/CN=Example Root CA"`,
		`pe.signatures[0].certificates[2].serial == "00:80:ab:cd"`,
		`pe.signatures[0].certificates[3].subject == "/CN=PKCS9 Timestamp Authority"`,
		`pe.signatures[0].certificates[4].subject == "/CN=RFC3161 TSA"`,
		`defined pe.signatures[0].signer_info.program_name`,
		`pe.signatures[0].signer_info.program_name == "PrimaryApp"`,
		`defined pe.signatures[0].signer_info.digest`,
		fmt.Sprintf(`pe.signatures[0].signer_info.digest == "%s"`, hex.EncodeToString(bytes.Repeat([]byte{0x22}, 32))),
		`defined pe.signatures[0].signer_info.digest_alg`,
		`pe.signatures[0].signer_info.digest_alg == "sha256"`,
		`pe.signatures[0].signer_info.length_of_chain == 0`,
		`pe.signatures[0].signer_info.length_of_chain == 1`,
		`pe.signatures[0].signer_info.length_of_chain == 3`,
		`pe.signatures[0].signer_info.chain[0].serial == "00:80:ab:cd"`,
		`pe.signatures[0].signer_info.chain[1].subject == "/C=US/O=Example Inter/CN=Example Intermediate CA"`,
		`pe.signatures[0].signer_info.chain[2].subject == "/C=US/O=Example Root/CN=Example Root CA"`,
		`pe.signatures[0].number_of_countersignatures == 0`,
		`pe.signatures[0].number_of_countersignatures == 2`,
		fmt.Sprintf(`pe.signatures[0].countersignatures[0].sign_time == %d`, sigTime.Unix()),
		fmt.Sprintf(`pe.signatures[0].countersignatures[0].digest == "%s"`, hex.EncodeToString(bytes.Repeat([]byte{0x33}, 32))),
		`pe.signatures[0].countersignatures[0].digest_alg == "sha256"`,
		`pe.signatures[0].countersignatures[0].length_of_chain == 1`,
		`pe.signatures[0].countersignatures[0].chain[0].subject == "/CN=PKCS9 Timestamp Authority"`,
		fmt.Sprintf(`pe.signatures[0].countersignatures[1].sign_time == %d`, tsaTime.Unix()),
		fmt.Sprintf(`pe.signatures[0].countersignatures[1].digest == "%s"`, hex.EncodeToString(bytes.Repeat([]byte{0x33}, 32))),
		`pe.signatures[0].countersignatures[1].digest_alg == "sha256"`,
		`pe.signatures[0].countersignatures[1].length_of_chain == 1`,
		`pe.signatures[0].countersignatures[1].chain[0].subject == "/CN=RFC3161 TSA"`,
		`pe.signatures[1].serial == "77:77"`,
		`pe.signatures[1].algorithm == "sha256WithRSAEncryption"`,
		`pe.signatures[1].algorithm_oid == "1.2.840.113549.1.1.11"`,
		fmt.Sprintf(`pe.signatures[1].thumbprint == "%s"`, hex.EncodeToString(nestedThumb[:])),
		`pe.signatures[1].signer_info.program_name == "NestedApp"`,
		`pe.signatures[1].signer_info.length_of_chain == 1`,
		`for any sig in pe.signatures : (sig.serial == "77:77")`,
		`for all cert in pe.signatures[0].certificates : (cert.version == 3)`,
	}

	source := peProbeSource(predicates)
	fixtures := map[string][]byte{
		"non_pe":             []byte("ordinary bytes"),
		"empty":              nil,
		"unsigned_pe32":      pefixture.New(false),
		"unsigned_pe64":      pefixture.New(true),
		"signed_pe32":        pefixture.WithCertificates(pefixture.New(false), pefixture.CertificateRecord{Type: 2, Payload: primaryBlob}),
		"signed_pe64":        pefixture.WithCertificates(pefixture.New(true), pefixture.CertificateRecord{Type: 2, Payload: primaryBlob}),
		"zero_serial":        pefixture.WithCertificates(pefixture.New(false), pefixture.CertificateRecord{Type: 2, Payload: zeroSerialBlob}),
		"empty_signer_infos": pefixture.WithCertificates(pefixture.New(false), pefixture.CertificateRecord{Type: 2, Payload: emptySignerBlob}),
	}
	for name, data := range fixtures {
		t.Run(name, func(t *testing.T) {
			checkPEPaths(t, source, data)
		})
	}
}
