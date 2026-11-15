package compiler

import (
	"bytes"
	"context"
	"crypto"
	"encoding/asn1"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pe "github.com/cawalch/go-pe"

	"github.com/cawalch/go-yara/internal/pefixture"
)

func authenticodeDigestForBase(t *testing.T, base []byte, alg crypto.Hash) []byte {
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

func TestPESignatureVerify(t *testing.T) {
	t.Run("algorithms_and_countersignatures", func(t *testing.T) {
		p, err := NewCompiler().CompileSource(`import "pe"
rule verified {
	condition:
		pe.is_signed == 1 and
		pe.number_of_signatures == 1 and
		pe.signatures[0].verified == 1
}
rule both_cs_verified {
	condition:
		pe.signatures[0].number_of_countersignatures == 2 and
		pe.signatures[0].countersignatures[0].verified == 1 and
		pe.signatures[0].countersignatures[1].verified == 1
}`)
		if err != nil {
			t.Fatal(err)
		}
		s := p.NewScanner()
		defer s.Close()

		ts := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
		cases := []struct {
			name   string
			is64   bool
			opts   pefixture.SignedAuthenticodeOptions
			wantCS bool
		}{
			{
				name: "pe32_rsa_sha256_countersigned",
				opts: pefixture.SignedAuthenticodeOptions{
					UseRSA:         true,
					ImageDigestAlg: crypto.SHA256,
					SigningTime:    ts,
					PKCS9At:        ts,
					RFC3161At:      ts,
				},
				wantCS: true,
			},
			{
				name: "pe32plus_ecdsa_sha256_countersigned",
				is64: true,
				opts: pefixture.SignedAuthenticodeOptions{
					ImageDigestAlg: crypto.SHA256,
					PKCS9At:        ts,
					RFC3161At:      ts,
				},
				wantCS: true,
			},
			{
				name: "rsa_sha1",
				opts: pefixture.SignedAuthenticodeOptions{
					UseRSA:         true,
					ImageDigestAlg: crypto.SHA1,
				},
			},
			{
				name: "rsa_md5",
				opts: pefixture.SignedAuthenticodeOptions{
					UseRSA:         true,
					ImageDigestAlg: crypto.MD5,
				},
			},
			{
				name: "rsa_pss_sha256",
				opts: pefixture.SignedAuthenticodeOptions{
					UseRSA:         true,
					UseRSAPSS:      true,
					ImageDigestAlg: crypto.SHA256,
				},
			},
			{
				name: "ecdsa_subject_key_id",
				opts: pefixture.SignedAuthenticodeOptions{
					ImageDigestAlg:  crypto.SHA256,
					UseSubjectKeyID: true,
				},
			},
			{
				name: "ed25519_sha256",
				opts: pefixture.SignedAuthenticodeOptions{
					UseEd25519:     true,
					ImageDigestAlg: crypto.SHA256,
				},
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				signed, _ := pefixture.SignedAuthenticodePE(tc.is64, nil, tc.opts)
				r, err := s.Scan(signed)
				if err != nil {
					t.Fatal(err)
				}
				if !r.RuleResults["verified"] || r.RuleResults["both_cs_verified"] != tc.wantCS {
					t.Fatalf("unexpected results %v (wantCS=%v)", r.RuleResults, tc.wantCS)
				}
			})
		}
	})

	t.Run("tampered_image_keeps_countersignatures_verified", func(t *testing.T) {
		base := pefixture.New(false)
		digest := authenticodeDigestForBase(t, base, crypto.SHA256)
		ts := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
		blob, _ := pefixture.VerifiedAuthenticodeBlob(digest, pefixture.SignedAuthenticodeOptions{
			UseRSA:         true,
			ImageDigestAlg: crypto.SHA256,
			PKCS9At:        ts,
			RFC3161At:      ts,
		})
		tamperedBase := append([]byte(nil), base...)
		tamperedBase[len(tamperedBase)-1] ^= 0xff
		signed := pefixture.WithCertificates(tamperedBase, pefixture.CertificateRecord{
			Revision: 0x0200,
			Type:     2,
			Payload:  blob,
		})

		p, err := NewCompiler().CompileSource(`import "pe"
rule tampered {
	condition:
		defined pe.is_signed and
		pe.is_signed == 0 and
		pe.signatures[0].verified == 0 and
		pe.signatures[0].countersignatures[0].verified == 1 and
		pe.signatures[0].countersignatures[1].verified == 1
}`)
		if err != nil {
			t.Fatal(err)
		}
		s := p.NewScanner()
		defer s.Close()
		r, err := s.Scan(signed)
		if err != nil || !r.RuleResults["tampered"] {
			t.Fatalf("expected tampered image digest with verified countersignatures, got %v err=%v", r, err)
		}
	})

	t.Run("unverified_and_faulted_signatures", func(t *testing.T) {
		p, err := NewCompiler().CompileSource(`import "pe"
rule unverified_sig {
	condition:
		defined pe.is_signed and
		pe.is_signed == 0 and
		pe.signatures[0].verified == 0
}`)
		if err != nil {
			t.Fatal(err)
		}
		s := p.NewScanner()
		defer s.Close()

		cases := []struct {
			name string
			opts pefixture.SignedAuthenticodeOptions
		}{
			{
				name: "corrupt_signature",
				opts: pefixture.SignedAuthenticodeOptions{UseRSA: true, CorruptSignature: true},
			},
			{
				name: "corrupt_signed_digest",
				opts: pefixture.SignedAuthenticodeOptions{UseRSA: true, CorruptSignedDigest: true},
			},
			{
				name: "missing_signer_cert",
				opts: pefixture.SignedAuthenticodeOptions{UseRSA: true, OmitSignerCert: true},
			},
			{
				name: "duplicate_message_digest",
				opts: pefixture.SignedAuthenticodeOptions{UseRSA: true, DuplicateMessageDigest: true},
			},
			{
				name: "duplicate_signing_time",
				opts: pefixture.SignedAuthenticodeOptions{
					UseRSA:               true,
					SigningTime:          time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
					DuplicateSigningTime: true,
				},
			},
			{
				name: "omitted_signed_attrs",
				opts: pefixture.SignedAuthenticodeOptions{UseRSA: true, OmitSignedAttrs: true},
			},
			{
				name: "unsupported_image_digest_oid",
				opts: pefixture.SignedAuthenticodeOptions{
					UseRSA:                 true,
					OverrideImageDigestOID: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 99},
				},
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				signed, _ := pefixture.SignedAuthenticodePE(false, nil, tc.opts)
				r, err := s.Scan(signed)
				if err != nil || !r.RuleResults["unverified_sig"] {
					t.Fatalf("%s: got %v err=%v", tc.name, r, err)
				}
			})
		}
	})

	t.Run("offline_timestamps_ignore_wall_clock_and_check_imprint", func(t *testing.T) {
		tsOutOfBounds := time.Date(2028, 6, 1, 0, 0, 0, 0, time.UTC)
		expiredAndOutOfBounds, _ := pefixture.SignedAuthenticodePE(false, nil, pefixture.SignedAuthenticodeOptions{
			UseRSA:    true,
			NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
			NotAfter:  time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
			PKCS9At:   tsOutOfBounds,
			RFC3161At: tsOutOfBounds,
		})
		badImprint, _ := pefixture.SignedAuthenticodePE(false, nil, pefixture.SignedAuthenticodeOptions{
			UseRSA:                  true,
			PKCS9At:                 time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
			RFC3161At:               time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
			CorruptTimestampImprint: true,
		})
		badTSSig, _ := pefixture.SignedAuthenticodePE(false, nil, pefixture.SignedAuthenticodeOptions{
			UseRSA:              true,
			PKCS9At:             time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
			RFC3161At:           time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
			CorruptTimestampSig: true,
		})

		p, err := NewCompiler().CompileSource(`import "pe"
rule sig_ok {
	condition:
		pe.is_signed == 1 and
		pe.signatures[0].verified == 1
}
rule ts_ok {
	condition:
		pe.signatures[0].countersignatures[0].verified == 1 and
		pe.signatures[0].countersignatures[1].verified == 1
}
rule ts_bad {
	condition:
		pe.signatures[0].countersignatures[0].verified == 0 and
		pe.signatures[0].countersignatures[1].verified == 0
}`)
		if err != nil {
			t.Fatal(err)
		}
		s := p.NewScanner()
		defer s.Close()

		r, err := s.Scan(expiredAndOutOfBounds)
		if err != nil || !r.RuleResults["sig_ok"] || !r.RuleResults["ts_ok"] {
			t.Fatalf("expired/out-of-bounds: %v err=%v", r, err)
		}
		for _, bad := range [][]byte{badImprint, badTSSig} {
			r, err := s.Scan(bad)
			if err != nil || !r.RuleResults["sig_ok"] || !r.RuleResults["ts_bad"] {
				t.Fatalf("bad timestamp: %v err=%v", r, err)
			}
		}
	})

	t.Run("nested_mixed_verification", func(t *testing.T) {
		base := pefixture.New(false)
		digest := authenticodeDigestForBase(t, base, crypto.SHA256)
		validNested, _ := pefixture.VerifiedAuthenticodeBlob(digest, pefixture.SignedAuthenticodeOptions{UseRSA: true})
		badNested, _ := pefixture.VerifiedAuthenticodeBlob(digest, pefixture.SignedAuthenticodeOptions{UseRSA: true, CorruptSignature: true})

		primaryBadNestedValid, _ := pefixture.SignedAuthenticodePE(false, base, pefixture.SignedAuthenticodeOptions{
			UseRSA:              true,
			CorruptSignedDigest: true,
			NestedBlobs:         [][]byte{validNested},
		})
		primaryValidNestedBad, _ := pefixture.SignedAuthenticodePE(false, base, pefixture.SignedAuthenticodeOptions{
			UseRSA:      true,
			NestedBlobs: [][]byte{badNested},
		})

		p, err := NewCompiler().CompileSource(`import "pe"
rule p_bad_n_ok {
	condition:
		pe.is_signed == 1 and
		pe.number_of_signatures == 2 and
		pe.signatures[0].verified == 0 and
		pe.signatures[1].verified == 1
}
rule p_ok_n_bad {
	condition:
		pe.is_signed == 1 and
		pe.number_of_signatures == 2 and
		pe.signatures[0].verified == 1 and
		pe.signatures[1].verified == 0
}`)
		if err != nil {
			t.Fatal(err)
		}
		s := p.NewScanner()
		defer s.Close()

		r1, err := s.Scan(primaryBadNestedValid)
		if err != nil || !r1.RuleResults["p_bad_n_ok"] {
			t.Fatalf("primaryBadNestedValid: %v err=%v", r1, err)
		}
		r2, err := s.Scan(primaryValidNestedBad)
		if err != nil || !r2.RuleResults["p_ok_n_bad"] {
			t.Fatalf("primaryValidNestedBad: %v err=%v", r2, err)
		}
	})

	t.Run("unsigned_non_pe_and_malformed_cms", func(t *testing.T) {
		p, err := NewCompiler().CompileSource(`import "pe"
rule unsigned_pe {
	condition:
		pe.is_pe == 1 and
		defined pe.is_signed and
		pe.is_signed == 0 and
		not defined pe.signatures[0].verified
}
rule undefined_all {
	condition:
		not defined pe.is_signed and
		not defined pe.signatures[0].verified and
		not defined pe.signatures[0].countersignatures[0].verified
}`)
		if err != nil {
			t.Fatal(err)
		}
		s := p.NewScanner()
		defer s.Close()

		rUnsigned, err := s.Scan(pefixture.New(false))
		if err != nil || !rUnsigned.RuleResults["unsigned_pe"] {
			t.Fatalf("unsigned PE: %v err=%v", rUnsigned, err)
		}
		for name, data := range map[string][]byte{
			"non_pe": []byte("ordinary non-pe payload"),
			"malformed_cms": pefixture.WithCertificates(pefixture.New(false), pefixture.CertificateRecord{
				Revision: 0x0200,
				Type:     2,
				Payload:  []byte{0x30, 0x80, 0x01, 0x02},
			}),
		} {
			r, err := s.Scan(data)
			if err != nil || !r.RuleResults["undefined_all"] || r.RuleResults["unsigned_pe"] {
				t.Fatalf("%s: %v err=%v", name, r, err)
			}
		}
	})

	t.Run("reader_block_and_mmap_file_semantics", func(t *testing.T) {
		smallSigned, _ := pefixture.SignedAuthenticodePE(false, nil, pefixture.SignedAuthenticodeOptions{UseRSA: true})
		// > 128 KiB to trigger ScanFile mmap/whole-file verification as well as > 64 KiB ScanReader truncation.
		paddedBase := make([]byte, 160*1024)
		copy(paddedBase, pefixture.New(false))
		largeSigned, _ := pefixture.SignedAuthenticodePE(false, paddedBase, pefixture.SignedAuthenticodeOptions{UseRSA: true})
		largeUnsigned := append([]byte(nil), paddedBase...)

		signedPath := filepath.Join(t.TempDir(), "large_signed.exe")
		if err := os.WriteFile(signedPath, largeSigned, 0o600); err != nil {
			t.Fatal(err)
		}

		p, err := NewCompiler().CompileSource(`import "pe"
rule verified {
	condition:
		defined pe.is_signed and
		pe.is_signed == 1 and
		pe.signatures[0].verified == 1
}
rule partial_undef {
	condition:
		pe.is_pe == 1 and
		not defined pe.is_signed and
		not defined pe.signatures[0].verified and
		not defined pe.signatures[0].countersignatures[0].verified
}`)
		if err != nil {
			t.Fatal(err)
		}
		s := p.NewScanner()
		defer s.Close()

		// ScanFile verifies large signed PE (> 128 KiB).
		rf, err := s.ScanFile(signedPath)
		if err != nil || !rf.RuleResults["verified"] {
			t.Fatalf("ScanFile(largeSigned): %v err=%v", rf, err)
		}
		// ScanReader <= 64 KiB succeeds.
		rrSmall, err := s.ScanReader(bytes.NewReader(smallSigned))
		if err != nil || !rrSmall.RuleResults["verified"] {
			t.Fatalf("ScanReader(smallSigned): %v err=%v", rrSmall, err)
		}
		// ScanReader > 64 KiB returns undefined for both signed and unsigned inputs.
		for name, data := range map[string][]byte{"large_signed": largeSigned, "large_unsigned": largeUnsigned} {
			rr, err := s.ScanReader(bytes.NewReader(data))
			if err != nil || !rr.RuleResults["partial_undef"] || rr.RuleResults["verified"] {
				t.Fatalf("ScanReader(%s): %v err=%v", name, rr, err)
			}
		}

		// BlockScanner with Base == 0 single complete block verifies.
		bsFull := p.NewBlockScanner()
		if err := bsFull.Scan(0, smallSigned); err != nil {
			t.Fatal(err)
		}
		rbFull, err := bsFull.Finish()
		bsFull.Close()
		if err != nil || !rbFull.RuleResults["verified"] {
			t.Fatalf("BlockScanner(base=0 full): %v err=%v", rbFull, err)
		}

		// Segmented BlockScanner (base=0 partial header block + second block) leaves whole-file fields undefined.
		bsSeg := p.NewBlockScanner()
		if err := bsSeg.Scan(0, smallSigned[:0x200]); err != nil {
			t.Fatal(err)
		}
		if err := bsSeg.Scan(0x200, smallSigned[0x200:]); err != nil {
			t.Fatal(err)
		}
		rbSeg, err := bsSeg.Finish()
		bsSeg.Close()
		if err != nil || !rbSeg.RuleResults["partial_undef"] || rbSeg.RuleResults["verified"] {
			t.Fatalf("BlockScanner(segmented): %v err=%v", rbSeg, err)
		}

		// Non-zero BlockScanner cannot parse PE headers.
		bsOffset := p.NewBlockScanner()
		if err := bsOffset.Scan(4096, smallSigned); err != nil {
			t.Fatal(err)
		}
		rbOffset, err := bsOffset.Finish()
		bsOffset.Close()
		if err != nil || rbOffset.RuleResults["verified"] || rbOffset.RuleResults["partial_undef"] {
			t.Fatalf("BlockScanner(base=4096): %v err=%v", rbOffset, err)
		}
	})

	t.Run("lazy_cache_non_materialization_and_cancel", func(t *testing.T) {
		signed, _ := pefixture.SignedAuthenticodePE(false, nil, pefixture.SignedAuthenticodeOptions{
			UseRSA:    true,
			PKCS9At:   time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
			RFC3161At: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
		})
		snapshot := append([]byte(nil), signed...)

		ctx := &MatchContext{Data: snapshot, FileSize: int64(len(snapshot)), moduleCache: &moduleCallCache{}}
		interp := NewInterpreter(nil)
		defer interp.Release()
		interp.SetMatchContext(ctx)
		interp.currentCompiledRule = &CompiledRule{nativePE: true}

		img := loadPE(ctx)
		if img == nil || img.file == nil {
			t.Fatal("expected parsed peImage")
		}
		if got := img.field("is_signed"); got.Type != ModuleInteger || got.Integer != 1 {
			t.Fatalf("is_signed = %+v, want 1", got)
		}
		if img.signatures == nil || !img.signatures.verificationDone || !img.signatures.verificationValid {
			t.Fatalf("unexpected verification cache state: %+v", img.signatures)
		}
		if img.signatures.details.Type != ModuleUndefined {
			t.Fatal("pe.is_signed materialized signature detail ModuleValue objects")
		}
		if img.sections.Type != ModuleUndefined || img.imports != nil || img.exports != nil {
			t.Fatal("pe.is_signed materialized unrelated PE caches")
		}
		clear(snapshot)
		ctx.Data, ctx.FileSize = nil, 0
		if got := img.field("is_signed"); got.Type != ModuleInteger || got.Integer != 1 {
			t.Fatalf("cached is_signed changed after input clear: %+v", got)
		}

		// Unsigned PE records verificationDone without panicking or erroring.
		uCtx := &MatchContext{Data: pefixture.New(false), FileSize: int64(len(pefixture.New(false))), moduleCache: &moduleCallCache{}}
		uImg := loadPE(uCtx)
		if got := uImg.field("is_signed"); got.Type != ModuleInteger || got.Integer != 0 {
			t.Fatalf("unsigned is_signed = %+v, want 0", got)
		}
		if uImg.signatures == nil || !uImg.signatures.verificationDone {
			t.Fatal("expected verificationDone cache marker on unsigned PE")
		}

		// nativePE=false refuses fallback.
		p, err := NewCompiler().CompileSource(`import "pe"
rule r { condition: pe.is_signed == 1 }`)
		if err != nil {
			t.Fatal(err)
		}
		interp2 := NewInterpreter(p.Rules[0].Bytecode)
		defer interp2.Release()
		canceledCtx, cancel := context.WithCancel(context.Background())
		cancel()
		mctx := &MatchContext{Data: signed, FileSize: int64(len(signed)), moduleCache: &moduleCallCache{}, cancelDone: canceledCtx.Done()}
		interp2.SetMatchContext(mctx)
		interp2.setCurrentCompiledRule(p.Rules[0])
		if err := interp2.Execute(); !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled Execute = %v, want context.Canceled", err)
		}
		if mctx.moduleCache.pe != nil && mctx.moduleCache.pe.signatures != nil && mctx.moduleCache.pe.signatures.verificationDone {
			t.Fatal("canceled verification mutated verificationDone cache")
		}
	})

	t.Run("host_snapshot_ownership", func(t *testing.T) {
		p, err := NewCompiler().CompileSource(`import "pe"
rule host_verified {
	condition:
		pe.is_signed == 1 and
		pe.signatures[0].verified == 1 and
		pe.signatures[0].countersignatures[0].verified == 1 and
		pe.signatures[1].verified == 0
}`)
		if err != nil {
			t.Fatal(err)
		}
		sigs := []map[string]any{
			{
				"verified":          int64(1),
				"countersignatures": []map[string]any{{"verified": int64(1)}},
			},
			{
				"verified": int64(0),
			},
		}
		snapshot := map[string]any{
			"is_signed":  int64(1),
			"signatures": sigs,
		}
		s := p.NewScanner(WithModuleData("pe", snapshot))
		defer s.Close()
		sigs[0]["verified"] = int64(0)
		clear(snapshot)

		r, err := s.Scan(pefixture.New(false))
		if err != nil || !r.RuleResults["host_verified"] {
			t.Fatalf("host snapshot failed: %v err=%v", r, err)
		}
		if s.moduleCache.pe != nil {
			t.Fatal("host snapshot unexpectedly parsed input into pe cache")
		}
	})

	t.Run("schema_compatibility_serialization_and_reuse", func(t *testing.T) {
		p, err := NewCompiler().CompileSource(`import "pe"
rule sig_verify {
	condition:
		pe.is_signed == 1 and
		pe.signatures[0].verified == 1 and
		pe.signatures[0].countersignatures[0].verified == 1
}`)
		if err != nil {
			t.Fatal(err)
		}
		blob, err := p.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		restored, err := UnmarshalCompiledProgram(blob)
		if err != nil {
			t.Fatal(err)
		}
		if !restored.Rules[0].nativePE {
			t.Fatal("expected nativePE=true after round-trip unmarshal")
		}

		signed, _ := pefixture.SignedAuthenticodePE(false, nil, pefixture.SignedAuthenticodeOptions{
			UseRSA:  true,
			PKCS9At: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
		})
		unsigned := pefixture.New(false)
		nonPE := []byte("non-pe")

		s := restored.NewScanner()
		defer s.Close()
		for i, tc := range []struct {
			data []byte
			want bool
		}{
			{signed, true},
			{unsigned, false},
			{nonPE, false},
			{nil, false},
			{signed, true},
		} {
			r, err := s.Scan(tc.data)
			if err != nil {
				t.Fatalf("step %d: %v", i, err)
			}
			if r.RuleResults["sig_verify"] != tc.want {
				t.Fatalf("step %d: got %v, want %v", i, r.RuleResults["sig_verify"], tc.want)
			}
		}

		// Programs serialized with previous peSignaturesSchema must still validate cleanly.
		prevProg, err := NewCompiler().CompileSource(`import "pe"
rule old_sig { condition: pe.number_of_signatures == 1 and pe.signatures[0].serial != "" }`)
		if err != nil {
			t.Fatal(err)
		}
		prevProg.moduleSchemas["pe"] = peSignaturesSchema
		prevBlob, err := prevProg.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		prevRestored, err := UnmarshalCompiledProgram(prevBlob)
		if err != nil {
			t.Fatal(err)
		}
		if !prevRestored.Rules[0].nativePE {
			t.Fatal("expected legacy peSignaturesSchema program to retain nativePE=true")
		}
		ps := prevRestored.NewScanner()
		defer ps.Close()
		pr, err := ps.Scan(signed)
		if err != nil || !pr.RuleResults["old_sig"] {
			t.Fatalf("legacy schema program scan failed: %v err=%v", pr, err)
		}
	})
}

func TestPESignatureVerifyNonPEAllocations(t *testing.T) {
	p, err := NewCompiler().CompileSource(`import "pe"
rule non_pe {
	condition:
		pe.is_signed == 1 or
		pe.signatures[0].verified == 1 or
		pe.signatures[0].countersignatures[0].verified == 1
}`)
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
		t.Fatalf("non-PE verification scan allocs = %.1f, want 0", allocs)
	}
}

func BenchmarkPESignatureVerify(b *testing.B) {
	ts := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	signed, _ := pefixture.SignedAuthenticodePE(false, nil, pefixture.SignedAuthenticodeOptions{
		UseRSA:    true,
		PKCS9At:   ts,
		RFC3161At: ts,
	})
	unsigned := pefixture.New(false)
	nonPE := []byte("ordinary non-pe payload bytes for baseline check")

	benchRule := func(b *testing.B, name, source string, data []byte) {
		b.Run(name, func(b *testing.B) {
			p, err := NewCompiler().CompileSource(source)
			if err != nil {
				b.Fatal(err)
			}
			s := p.NewScanner(WithoutMatches(), WithoutRuleResults())
			b.Cleanup(s.Close)
			b.SetBytes(int64(len(data)))
			b.ReportAllocs()
			for b.Loop() {
				if _, err := s.MatchingRules(data); err != nil {
					b.Fatal(err)
				}
			}
		})
	}

	benchRule(b, "unused_pe/signed", `rule plain { strings: $a = "unused" condition: $a }`, signed)
	benchRule(b, "header_only/signed", `import "pe" rule hdr { condition: pe.is_pe == 1 and pe.machine == pe.MACHINE_I386 }`, signed)
	benchRule(b, "is_signed_only/non_pe", `import "pe" rule sig { condition: pe.is_signed == 1 }`, nonPE)
	benchRule(b, "is_signed_only/unsigned_pe", `import "pe" rule sig { condition: pe.is_signed == 1 }`, unsigned)
	benchRule(b, "metadata_only/signed", `import "pe" rule sig_meta { condition: pe.number_of_signatures > 0 and pe.signatures[0].serial != "" }`, signed)
	benchRule(b, "is_signed_only/signed", `import "pe" rule sig { condition: pe.is_signed == 1 }`, signed)
	benchRule(b, "verified_and_countersignature/signed", `import "pe" rule full { condition: pe.signatures[0].verified == 1 and pe.signatures[0].countersignatures[0].verified == 1 }`, signed)

	b.Run("setup/compile_and_new_scanner", func(b *testing.B) {
		src := strings.TrimSpace(`import "pe"
rule full { condition: pe.is_signed == 1 and pe.signatures[0].verified == 1 }`)
		b.ReportAllocs()
		for b.Loop() {
			p, err := NewCompiler().CompileSource(src)
			if err != nil {
				b.Fatal(err)
			}
			s := p.NewScanner()
			s.Close()
		}
	})
}
