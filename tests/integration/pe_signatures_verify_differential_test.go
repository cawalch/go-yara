package integration

import (
	"context"
	"crypto"
	"encoding/asn1"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pe "github.com/cawalch/go-pe"

	"github.com/cawalch/go-yara/compiler"
	"github.com/cawalch/go-yara/internal/pefixture"
)

func authenticodeDigest(t *testing.T, base []byte, alg crypto.Hash) []byte {
	t.Helper()
	aligned := append([]byte(nil), base...)
	for len(aligned)%8 != 0 {
		aligned = append(aligned, 0)
	}
	f, err := pe.New(aligned)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := f.AuthenticodeDigest(aligned, alg)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func TestLibyaraPESignatureVerifyDifferential(t *testing.T) {
	oracle := libyaraOracle(t)
	ts := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)

	tamperedBase := pefixture.New(false)
	tamperedDigest := authenticodeDigest(t, tamperedBase, crypto.SHA256)
	tamperedBlob, _ := pefixture.VerifiedAuthenticodeBlob(tamperedDigest, pefixture.SignedAuthenticodeOptions{
		UseRSA:         true,
		ImageDigestAlg: crypto.SHA256,
		PKCS9At:        ts,
		RFC3161At:      ts,
	})
	tamperedBytes := append([]byte(nil), tamperedBase...)
	tamperedBytes[len(tamperedBytes)-1] ^= 0xff
	tamperedPE := pefixture.WithCertificates(tamperedBytes, pefixture.CertificateRecord{
		Revision: 0x0200,
		Type:     2,
		Payload:  tamperedBlob,
	})

	nestedBase := pefixture.New(false)
	nestedDigest := authenticodeDigest(t, nestedBase, crypto.SHA256)
	nestedValidBlob, _ := pefixture.VerifiedAuthenticodeBlob(nestedDigest, pefixture.SignedAuthenticodeOptions{UseRSA: true})
	nestedBadBlob, _ := pefixture.VerifiedAuthenticodeBlob(nestedDigest, pefixture.SignedAuthenticodeOptions{UseRSA: true, CorruptSignature: true})

	rsaSigned, _ := pefixture.SignedAuthenticodePE(false, nil, pefixture.SignedAuthenticodeOptions{
		UseRSA:    true,
		PKCS9At:   ts,
		RFC3161At: ts,
	})
	ecdsaSigned, _ := pefixture.SignedAuthenticodePE(true, nil, pefixture.SignedAuthenticodeOptions{
		RFC3161At: ts,
	})
	rsaMD5Signed, _ := pefixture.SignedAuthenticodePE(false, nil, pefixture.SignedAuthenticodeOptions{
		UseRSA:         true,
		ImageDigestAlg: crypto.MD5,
	})
	corruptSig, _ := pefixture.SignedAuthenticodePE(false, nil, pefixture.SignedAuthenticodeOptions{
		UseRSA:           true,
		CorruptSignature: true,
	})
	corruptDigest, _ := pefixture.SignedAuthenticodePE(false, nil, pefixture.SignedAuthenticodeOptions{
		UseRSA:              true,
		CorruptSignedDigest: true,
	})
	missingCert, _ := pefixture.SignedAuthenticodePE(false, nil, pefixture.SignedAuthenticodeOptions{
		UseRSA:         true,
		OmitSignerCert: true,
	})
	expiredOutOfBounds, _ := pefixture.SignedAuthenticodePE(false, nil, pefixture.SignedAuthenticodeOptions{
		UseRSA:    true,
		NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:  time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
		PKCS9At:   time.Date(2028, 6, 1, 0, 0, 0, 0, time.UTC),
		RFC3161At: time.Date(2028, 6, 1, 0, 0, 0, 0, time.UTC),
	})
	badTSImprint, _ := pefixture.SignedAuthenticodePE(false, nil, pefixture.SignedAuthenticodeOptions{
		UseRSA:                  true,
		PKCS9At:                 ts,
		RFC3161At:               ts,
		CorruptTimestampImprint: true,
	})
	primaryBadNestedValid, _ := pefixture.SignedAuthenticodePE(false, nestedBase, pefixture.SignedAuthenticodeOptions{
		UseRSA:              true,
		CorruptSignedDigest: true,
		NestedBlobs:         [][]byte{nestedValidBlob},
	})
	primaryValidNestedBad, _ := pefixture.SignedAuthenticodePE(false, nestedBase, pefixture.SignedAuthenticodeOptions{
		UseRSA:      true,
		NestedBlobs: [][]byte{nestedBadBlob},
	})
	unknownOID, _ := pefixture.SignedAuthenticodePE(false, nil, pefixture.SignedAuthenticodeOptions{
		UseRSA:                 true,
		OverrideImageDigestOID: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 99},
	})

	source := peProbeSource([]string{
		`defined pe.is_signed`,
		`pe.is_signed == 0`,
		`pe.is_signed == 1`,
		`pe.number_of_signatures == 0`,
		`pe.number_of_signatures == 1`,
		`pe.number_of_signatures == 2`,
		`defined pe.signatures[0].verified`,
		`pe.signatures[0].verified == 0`,
		`pe.signatures[0].verified == 1`,
		`defined pe.signatures[1].verified`,
		`pe.signatures[1].verified == 0`,
		`pe.signatures[1].verified == 1`,
		`pe.signatures[0].number_of_countersignatures == 0`,
		`pe.signatures[0].number_of_countersignatures == 2`,
		`defined pe.signatures[0].countersignatures[0].verified`,
		`pe.signatures[0].countersignatures[0].verified == 0`,
		`pe.signatures[0].countersignatures[0].verified == 1`,
		`pe.signatures[0].countersignatures[1].verified == 0`,
		`pe.signatures[0].countersignatures[1].verified == 1`,
	})

	cases := map[string][]byte{
		"rsa_sha256_countersigned":               rsaSigned,
		"pe32plus_ecdsa_sha256_countersigned":    ecdsaSigned,
		"rsa_md5":                                rsaMD5Signed,
		"tampered_image_valid_countersignatures": tamperedPE,
		"corrupt_cms_signature":                  corruptSig,
		"corrupt_signed_digest":                  corruptDigest,
		"expired_cert_out_of_bounds_timestamp":   expiredOutOfBounds,
		"bad_timestamp_imprint":                  badTSImprint,
		"nested_primary_bad_nested_valid":        primaryBadNestedValid,
		"nested_primary_valid_nested_bad":        primaryValidNestedBad,
		"unknown_digest_oid":                     unknownOID,
		"unsigned_pe":                            pefixture.New(false),
		"non_pe":                                 []byte("ordinary non-pe payload"),
	}

	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			checkPEPaths(t, source, data)
		})
	}

	// Intentional strict-parser differences documented for #481:
	// 1. Malformed CMS blobs leave pe.is_signed and signatures undefined in go-yara,
	//    while libyara reports defined pe.is_signed == 0.
	// 2. Duplicate signed attributes (messageDigest / signingTime) are rejected as
	//    unverified (0) by go-pe, whereas OpenSSL PKCS7_verify can accept duplicates.
	// 3. Ed25519 CMS signatures are verified offline by go-pe, whereas libyara returns 0.
	t.Run("intentional_strict_differences", func(t *testing.T) {
		malformed := pefixture.WithCertificates(pefixture.New(false), pefixture.CertificateRecord{
			Revision: 0x0200,
			Type:     2,
			Payload:  []byte{0x30, 0x80, 0x01, 0x02},
		})
		srcMalformed := `import "pe"
rule go_strict_undef { condition: not defined pe.is_signed and not defined pe.signatures[0].verified }
rule lib_zero { condition: defined pe.is_signed and pe.is_signed == 0 }`

		pMalformed, err := compiler.NewCompiler().CompileSourceWithContext(context.Background(), srcMalformed)
		if err != nil {
			t.Fatal(err)
		}
		sMalformed := pMalformed.NewScanner()
		defer sMalformed.Close()
		gr, err := sMalformed.Scan(malformed)
		if err != nil || !gr.RuleResults["go_strict_undef"] || gr.RuleResults["lib_zero"] {
			t.Fatalf("go-yara malformed CMS: %v err=%v", gr, err)
		}
		lr, err := scanWithLibyara(t, oracle, srcMalformed, malformed)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := lr["lib_zero"]; !ok {
			t.Fatalf("libyara malformed CMS unexpected (behavior changed?): %v", lr)
		}

		dupAttr, _ := pefixture.SignedAuthenticodePE(false, nil, pefixture.SignedAuthenticodeOptions{
			UseRSA:                 true,
			DuplicateMessageDigest: true,
		})
		srcVerify := `import "pe" rule v { condition: pe.is_signed == 1 and pe.signatures[0].verified == 1 }`
		pDup, err := compiler.NewCompiler().CompileSourceWithContext(context.Background(), srcVerify)
		if err != nil {
			t.Fatal(err)
		}
		sDup := pDup.NewScanner()
		defer sDup.Close()
		gd, err := sDup.Scan(dupAttr)
		if err != nil || gd.RuleResults["v"] {
			t.Fatalf("go-yara should reject duplicate messageDigest: %v err=%v", gd, err)
		}

		edSigned, _ := pefixture.SignedAuthenticodePE(false, nil, pefixture.SignedAuthenticodeOptions{
			UseEd25519: true,
		})
		ge, err := sDup.Scan(edSigned)
		if err != nil || !ge.RuleResults["v"] {
			t.Fatalf("go-yara should verify Ed25519 offline: %v err=%v", ge, err)
		}
		le, err := scanWithLibyara(t, oracle, srcVerify, edSigned)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := le["v"]; ok {
			t.Fatalf("unexpected libyara Ed25519 pass: %v", le)
		}

		// Missing signer cert: both report pe.is_signed == 0, while go-yara retains
		// signature metadata (number_of_signatures == 1, verified == 0) and libyara
		// drops the unresolvable signature (number_of_signatures == 0).
		srcMissing := `import "pe"
rule not_signed { condition: defined pe.is_signed and pe.is_signed == 0 }
rule go_keeps_meta { condition: pe.number_of_signatures == 1 and pe.signatures[0].verified == 0 }
rule lib_drops_meta { condition: pe.number_of_signatures == 0 }`
		pMissing, err := compiler.NewCompiler().CompileSourceWithContext(context.Background(), srcMissing)
		if err != nil {
			t.Fatal(err)
		}
		sMissing := pMissing.NewScanner()
		defer sMissing.Close()
		gm, err := sMissing.Scan(missingCert)
		if err != nil || !gm.RuleResults["not_signed"] || !gm.RuleResults["go_keeps_meta"] {
			t.Fatalf("go-yara missing signer cert: %v err=%v", gm, err)
		}
		lm, err := scanWithLibyara(t, oracle, srcMissing, missingCert)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := lm["not_signed"]; !ok {
			t.Fatalf("libyara missing signer cert expected is_signed == 0: %v", lm)
		}
		if _, ok := lm["lib_drops_meta"]; !ok {
			t.Fatalf("libyara missing signer cert unexpected metadata: %v", lm)
		}

		// ECDSA PKCS#9 countersignatures: go-pe verifies ECDSA PKCS#9 SignerInfo,
		// whereas libyara's legacy PKCS#9 path reports countersignatures[0].verified == 0.
		ecdsaPKCS9, _ := pefixture.SignedAuthenticodePE(false, nil, pefixture.SignedAuthenticodeOptions{
			PKCS9At: ts,
		})
		srcCS := `import "pe"
rule sig_ok { condition: pe.is_signed == 1 and pe.signatures[0].verified == 1 }
rule cs_ok { condition: pe.signatures[0].countersignatures[0].verified == 1 }`
		pCS, err := compiler.NewCompiler().CompileSourceWithContext(context.Background(), srcCS)
		if err != nil {
			t.Fatal(err)
		}
		sCS := pCS.NewScanner()
		defer sCS.Close()
		gc, err := sCS.Scan(ecdsaPKCS9)
		if err != nil || !gc.RuleResults["sig_ok"] || !gc.RuleResults["cs_ok"] {
			t.Fatalf("go-yara ECDSA PKCS#9: %v err=%v", gc, err)
		}
		lc, err := scanWithLibyara(t, oracle, srcCS, ecdsaPKCS9)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := lc["sig_ok"]; !ok {
			t.Fatalf("libyara ECDSA PKCS#9 sig_ok expected true: %v", lc)
		}
		if _, ok := lc["cs_ok"]; ok {
			t.Fatalf("libyara ECDSA PKCS#9 cs_ok unexpectedly true: %v", lc)
		}
	})

	t.Run("real_world_cached_fixtures", func(t *testing.T) {
		out, err := exec.Command("go", "env", "GOMODCACHE").Output()
		if err != nil {
			t.Skipf("go env GOMODCACHE failed: %v", err)
		}
		cache := strings.TrimSpace(string(out))
		matches, _ := filepath.Glob(filepath.Join(cache, "github.com/foxboron/go-uefi*"))
		if len(matches) == 0 {
			t.Skip("go-uefi fixtures not present in GOMODCACHE")
		}
		root := matches[0]
		rels := []string{
			"authenticode/testdata/test.pecoff.signed",
			"authenticode/testdata/test.pecoff",
			"tests/data/binary/HelloWorld.efi.signed",
		}
		foundAny := false
		for _, rel := range rels {
			data, err := os.ReadFile(filepath.Join(root, rel))
			if err != nil {
				continue
			}
			foundAny = true
			t.Run(filepath.Base(rel), func(t *testing.T) {
				checkPEPaths(t, source, data)
			})
		}
		if !foundAny {
			t.Skip("no cached PECOFF fixtures readable")
		}
	})
}
