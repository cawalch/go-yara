package compiler

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cawalch/go-yara/internal/pefixture"
)

func TestPESignaturesMetadataAndFormatting(t *testing.T) {
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
		Serial:             new(big.Int).SetBytes([]byte{0x80, 0xab, 0xcd}), // High-bit DER INTEGER has leading 0x00.
		NotBefore:          time.Date(1960, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:           time.Date(2060, 1, 1, 0, 0, 0, 0, time.UTC),
		IncludeChain:       true,
		IndirectDigest:     bytes.Repeat([]byte{0x11}, 20),
		IndirectDigestOID:  asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}, // sha1
		MessageDigest:      bytes.Repeat([]byte{0x22}, 32),
		ProgramName:        "PrimaryApp",
		PKCS9CountersignAt: sigTime,
		CountersignDigest:  bytes.Repeat([]byte{0x33}, 32),
		RFC3161TimestampAt: tsaTime,
		NestedBlobs:        [][]byte{nestedBlob},
	})
	primaryThumb := sha1.Sum(primaryCert.Raw)

	for _, is64 := range []bool{false, true} {
		t.Run(fmt.Sprintf("pe64=%t", is64), func(t *testing.T) {
			signed := pefixture.WithCertificates(
				pefixture.New(is64),
				pefixture.CertificateRecord{Type: 1, Payload: []byte{1, 2, 3}}, // Non-PKCS7 skipped cleanly.
				pefixture.CertificateRecord{Type: 2, Payload: primaryBlob},
			)
			unsigned := pefixture.New(is64)

			source := fmt.Sprintf(`import "pe"
rule counts {
	condition:
		pe.number_of_signatures == 2 and
		pe.signatures[0].number_of_certificates == 5 and
		pe.signatures[0].number_of_countersignatures == 2 and
		pe.signatures[0].signer_info.length_of_chain == 3 and
		pe.signatures[1].signer_info.length_of_chain == 1
}
rule primary_fields {
	condition:
		pe.signatures[0].serial == "00:80:ab:cd" and
		pe.signatures[0].version == 3 and
		pe.signatures[0].algorithm == "ecdsa-with-SHA256" and
		pe.signatures[0].algorithm_oid == "1.2.840.10045.4.3.2" and
		pe.signatures[0].thumbprint == "%s" and
		pe.signatures[0].issuer == "/C=US/O=Example Inter/CN=Example Intermediate CA" and
		pe.signatures[0].subject == "/C=US/ST=California/L=Mountain View/O=Example Corp, Inc./OU=Team=Alpha+OU=Security/Ops/CN=Primary / \\xC3\\x9CTF8/emailAddress=sec@example.invalid/1.2.3.4.5=ext" and
		pe.signatures[0].not_before == -315619200 and
		pe.signatures[0].not_after == 2840140800 and
		pe.signatures[0].not_before < 0 and
		pe.signatures[0].not_after > 2147483647 and
		pe.signatures[0].not_after < %d and
		pe.signatures[0].digest == "%s" and
		pe.signatures[0].digest_alg == "sha1"
}
rule signer_and_chains {
	condition:
		pe.signatures[0].signer_info.program_name == "PrimaryApp" and
		pe.signatures[0].signer_info.digest == "%s" and
		pe.signatures[0].signer_info.digest_alg == "sha256" and
		pe.signatures[0].signer_info.chain[0].serial == "00:80:ab:cd" and
		pe.signatures[0].signer_info.chain[1].subject == "/C=US/O=Example Inter/CN=Example Intermediate CA" and
		pe.signatures[0].signer_info.chain[2].subject == "/C=US/O=Example Root/CN=Example Root CA" and
		pe.signatures[0].certificates[0].subject == "/C=US/O=Example Root/CN=Example Root CA" and
		pe.signatures[0].certificates[2].serial == "00:80:ab:cd" and
		pe.signatures[0].certificates[3].subject == "/CN=PKCS9 Timestamp Authority" and
		pe.signatures[0].certificates[4].subject == "/CN=RFC3161 TSA"
}
rule countersigs_and_nested {
	condition:
		pe.signatures[0].countersignatures[0].sign_time == %d and
		pe.signatures[0].countersignatures[0].digest == "%s" and
		pe.signatures[0].countersignatures[0].digest_alg == "sha256" and
		pe.signatures[0].countersignatures[0].length_of_chain == 1 and
		pe.signatures[0].countersignatures[0].chain[0].subject == "/CN=PKCS9 Timestamp Authority" and
		pe.signatures[0].countersignatures[1].sign_time == %d and
		pe.signatures[0].countersignatures[1].digest == "%s" and
		pe.signatures[0].countersignatures[1].digest_alg == "sha256" and
		pe.signatures[0].countersignatures[1].length_of_chain == 1 and
		pe.signatures[0].countersignatures[1].chain[0].subject == "/CN=RFC3161 TSA" and
		pe.signatures[1].serial == "77:77" and
		pe.signatures[1].algorithm == "sha256WithRSAEncryption" and
		pe.signatures[1].thumbprint == "%s" and
		pe.signatures[1].signer_info.program_name == "NestedApp"
}
rule unsigned_pe {
	condition:
		pe.is_pe == 1 and pe.number_of_signatures == 0 and not defined pe.signatures[0].serial
}
rule non_pe {
	condition:
		pe.is_pe == 0 and not defined pe.number_of_signatures and not defined pe.signatures[0].serial
}`,
				hex.EncodeToString(primaryThumb[:]),
				math.MaxInt64,
				hex.EncodeToString(bytes.Repeat([]byte{0x11}, 20)),
				hex.EncodeToString(bytes.Repeat([]byte{0x22}, 32)),
				sigTime.Unix(),
				hex.EncodeToString(bytes.Repeat([]byte{0x33}, 32)),
				tsaTime.Unix(),
				hex.EncodeToString(bytes.Repeat([]byte{0x33}, 32)),
				hex.EncodeToString(nestedThumb[:]),
			)

			p, err := NewCompiler().CompileSource(source)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := p.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			loaded, err := UnmarshalCompiledProgram(encoded)
			if err != nil {
				t.Fatal(err)
			}

			for _, prog := range []*CompiledProgram{p, loaded} {
				s := prog.NewScanner()
				defer s.Close()

				for _, viaReader := range []bool{false, true} {
					var r *ScanResult
					if viaReader {
						r, err = s.ScanReader(bytes.NewReader(signed))
					} else {
						r, err = s.Scan(signed)
					}
					if err != nil {
						t.Fatalf("signed scan (reader=%t): %v", viaReader, err)
					}
					for _, want := range []string{"counts", "primary_fields", "signer_and_chains", "countersigs_and_nested"} {
						if !r.RuleResults[want] {
							t.Fatalf("signed (reader=%t): rule %s false: %v", viaReader, want, r.RuleResults)
						}
					}
					if r.RuleResults["unsigned_pe"] || r.RuleResults["non_pe"] {
						t.Fatalf("signed unexpectedly matched unsigned/non_pe: %v", r.RuleResults)
					}
				}

				// Verify scanner reuse resets signature cache across unsigned and non-PE inputs.
				rUnsigned, err := s.Scan(unsigned)
				if err != nil || !rUnsigned.RuleResults["unsigned_pe"] || rUnsigned.RuleResults["counts"] {
					t.Fatalf("unsigned reuse failed: %v %v", rUnsigned, err)
				}
				rNonPE, err := s.Scan([]byte("ordinary bytes"))
				if err != nil || !rNonPE.RuleResults["non_pe"] || rNonPE.RuleResults["unsigned_pe"] {
					t.Fatalf("non_pe reuse failed: %v %v", rNonPE, err)
				}
			}
		})
	}
}

func TestPESignaturesEdgeCasesAndErrors(t *testing.T) {
	t.Run("subject_key_id_and_unknown_algo", func(t *testing.T) {
		blob, _ := pefixture.AuthenticodeBlob(pefixture.AuthenticodeOptions{
			Serial:            big.NewInt(0),
			UseSubjectKeyID:   true,
			UnknownCertSigOID: asn1.ObjectIdentifier{1, 2, 3, 999, 77},
			IndirectDigestOID: asn1.ObjectIdentifier{1, 2, 3, 999, 1},
			OmitSignedAttrs:   true,
		})
		data := pefixture.WithCertificates(pefixture.New(false), pefixture.CertificateRecord{Type: 2, Payload: blob})
		p, err := NewCompiler().CompileSource(`import "pe"
rule nsig { condition: pe.number_of_signatures == 1 }
rule ser { condition: pe.signatures[0].serial == "00" }
rule algo { condition: pe.signatures[0].algorithm == "undefined" }
rule oid { condition: pe.signatures[0].algorithm_oid == "1.2.3.999.77" }
rule dalg { condition: pe.signatures[0].digest_alg == "undefined" }
rule nprog { condition: not defined pe.signatures[0].signer_info.program_name }
rule ndig { condition: not defined pe.signatures[0].signer_info.digest }
rule ndalg { condition: not defined pe.signatures[0].signer_info.digest_alg }
rule chain1 { condition: pe.signatures[0].signer_info.length_of_chain == 1 }`)
		if err != nil {
			t.Fatal(err)
		}
		s := p.NewScanner()
		defer s.Close()
		r, err := s.Scan(data)
		if err != nil {
			t.Fatal(err)
		}
		for name, ok := range r.RuleResults {
			if !ok {
				t.Fatalf("failed rule %s: %v", name, r.RuleResults)
			}
		}
	})

	t.Run("empty_certificates_and_empty_signer_infos", func(t *testing.T) {
		noCerts, _ := pefixture.AuthenticodeBlob(pefixture.AuthenticodeOptions{OmitCertificates: true})
		noSigners, _ := pefixture.AuthenticodeBlob(pefixture.AuthenticodeOptions{OmitSignerInfos: true})
		p, err := NewCompiler().CompileSource(`import "pe"
rule r {
	condition:
		pe.number_of_signatures == 1 and
		not defined pe.signatures[0].serial and
		not defined pe.signatures[0].subject and
		pe.signatures[0].signer_info.length_of_chain == 0 and
		defined pe.signatures[0].digest
}`)
		if err != nil {
			t.Fatal(err)
		}
		s := p.NewScanner()
		defer s.Close()
		for _, blob := range [][]byte{noCerts, noSigners} {
			data := pefixture.WithCertificates(pefixture.New(false), pefixture.CertificateRecord{Type: 2, Payload: blob})
			r, err := s.Scan(data)
			if err != nil || !r.RuleResults["r"] {
				t.Fatalf("blob failed: %v err=%v", r, err)
			}
		}
	})

	t.Run("malformed_cms_and_truncated_security_dir", func(t *testing.T) {
		malformed := pefixture.WithCertificates(pefixture.New(false), pefixture.CertificateRecord{
			Type:    2,
			Payload: []byte{0x30, 0x03, 0x01, 0x02, 0x03},
		})
		truncated := pefixture.New(false)
		binary.LittleEndian.PutUint32(truncated[peSecurityDirOffset(false):], 0x7f0)
		binary.LittleEndian.PutUint32(truncated[peSecurityDirOffset(false)+4:], 0x100)

		p, err := NewCompiler().CompileSource(`import "pe"
rule strict_undefined {
	condition:
		pe.is_pe == 1 and not defined pe.number_of_signatures and not defined pe.signatures[0].serial
}`)
		if err != nil {
			t.Fatal(err)
		}
		s := p.NewScanner()
		defer s.Close()
		for _, input := range [][]byte{malformed, truncated} {
			r, err := s.Scan(input)
			if err != nil || !r.RuleResults["strict_undefined"] {
				t.Fatalf("expected strict undefined, got %v err=%v", r, err)
			}
		}
	})

	t.Run("large_reader_truncation_vs_file_and_blocks", func(t *testing.T) {
		blob, _ := pefixture.AuthenticodeBlob(pefixture.AuthenticodeOptions{
			Serial: big.NewInt(0x42),
		})
		base := pefixture.New(false)
		// Pad beyond streamingHeaderSize (64 KiB) before attaching security directory.
		padded := make([]byte, streamingHeaderSize+1024)
		copy(padded, base)
		largeSigned := pefixture.WithCertificates(padded, pefixture.CertificateRecord{Type: 2, Payload: blob})

		path := filepath.Join(t.TempDir(), "large_signed.exe")
		if err := os.WriteFile(path, largeSigned, 0o600); err != nil {
			t.Fatal(err)
		}

		p, err := NewCompiler().CompileSource(`import "pe"
rule present { condition: pe.number_of_signatures == 1 and pe.signatures[0].serial == "42" }
rule undef { condition: pe.is_pe == 1 and not defined pe.number_of_signatures }`)
		if err != nil {
			t.Fatal(err)
		}
		s := p.NewScanner()
		defer s.Close()

		rFile, err := s.ScanFile(path)
		if err != nil || !rFile.RuleResults["present"] {
			t.Fatalf("ScanFile: %v %v", rFile, err)
		}
		// Reader truncates tail after 64 KiB prefix -> signature table past EOF -> undefined.
		rReader, err := s.ScanReader(bytes.NewReader(largeSigned))
		if err != nil || !rReader.RuleResults["undef"] {
			t.Fatalf("ScanReader: %v %v", rReader, err)
		}
		// Non-zero base BlockScanner cannot locate headers -> not PE.
		b := p.NewBlockScanner()
		if err := b.Scan(4096, largeSigned); err != nil {
			t.Fatal(err)
		}
		rBlock, err := b.Finish()
		b.Close()
		if err != nil || rBlock.RuleResults["present"] || rBlock.RuleResults["undef"] {
			t.Fatalf("non-zero block: %v %v", rBlock, err)
		}
	})

	t.Run("host_snapshot_ownership", func(t *testing.T) {
		p, err := NewCompiler().CompileSource(`import "pe"
rule host_sig {
	condition:
		pe.number_of_signatures == 1 and
		pe.signatures[0].serial == "aa:bb" and
		pe.signatures[0].not_after == 9223372036854775807 and
		pe.signatures[0].signer_info.chain[0].subject == "/CN=Host" and
		pe.signatures[0].countersignatures[0].sign_time == 1700000000
}`)
		if err != nil {
			t.Fatal(err)
		}
		sigs := []map[string]any{{
			"serial":            "aa:bb",
			"not_after":         int64(math.MaxInt64),
			"signer_info":       map[string]any{"chain": []map[string]any{{"subject": "/CN=Host"}}},
			"countersignatures": []map[string]any{{"sign_time": int64(1700000000)}},
		}}
		snapshot := map[string]any{
			"number_of_signatures": 1,
			"signatures":           sigs,
		}
		s := p.NewScanner(WithModuleData("pe", snapshot))
		defer s.Close()
		// Mutate caller data after WithModuleData to prove ownership.
		sigs[0]["serial"] = "00"
		clear(snapshot)

		r, err := s.Scan(pefixture.New(false))
		if err != nil || !r.RuleResults["host_sig"] {
			t.Fatalf("host snapshot failed: %v err=%v", r, err)
		}
	})

	t.Run("canceled_context", func(t *testing.T) {
		blob, _ := pefixture.AuthenticodeBlob(pefixture.AuthenticodeOptions{})
		signed := pefixture.WithCertificates(pefixture.New(false), pefixture.CertificateRecord{Type: 2, Payload: blob})
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		img := &peImage{context: &MatchContext{Data: signed, FileSize: int64(len(signed)), cancelDone: ctx.Done()}}
		if got := img.loadSignatures(); got.valid {
			t.Fatal("expected canceled loadSignatures to leave data invalid/undefined")
		}
	})

	t.Run("valid_on_remains_unsupported", func(t *testing.T) {
		if _, err := NewCompiler().CompileSource(`import "pe" rule r { condition: pe.signatures[0].valid_on(1700000000) }`); err == nil {
			t.Fatal("expected pe.signatures[0].valid_on to be rejected")
		}
	})
}

func TestPESignaturesNonPEAllocations(t *testing.T) {
	p, err := NewCompiler().CompileSource(`import "pe"
rule non_pe { condition: pe.number_of_signatures > 0 or pe.signatures[0].serial == "01" or defined pe.signatures[0].signer_info.program_name }`)
	if err != nil {
		t.Fatal(err)
	}
	s := p.NewScanner(WithoutMatches(), WithoutRuleResults())
	defer s.Close()
	data := []byte("ordinary non-pe input bytes")
	allocs := testing.AllocsPerRun(100, func() {
		if _, err := s.MatchingRules(data); err != nil {
			t.Fatal(err)
		}
	})
	if allocs != 0 {
		t.Fatalf("non-PE signature scan allocs = %.1f, want 0", allocs)
	}
}

func BenchmarkPESignatures(b *testing.B) {
	blob, _ := pefixture.AuthenticodeBlob(pefixture.AuthenticodeOptions{
		IncludeChain:       true,
		PKCS9CountersignAt: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
	})
	signed := pefixture.WithCertificates(pefixture.New(false), pefixture.CertificateRecord{Type: 2, Payload: blob})
	unsigned := pefixture.New(false)
	nonPE := []byte("ordinary non-pe payload bytes for baseline check")

	p, err := NewCompiler().CompileSource(`import "pe"
rule sig { condition: pe.number_of_signatures > 0 and pe.signatures[0].serial == "12:34:56" }`)
	if err != nil {
		b.Fatal(err)
	}
	s := p.NewScanner()
	b.Cleanup(s.Close)

	for name, data := range map[string][]byte{
		"non_pe":   nonPE,
		"unsigned": unsigned,
		"signed":   signed,
	} {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := s.Scan(data); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
