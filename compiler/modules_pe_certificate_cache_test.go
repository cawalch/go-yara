package compiler

import (
	"crypto/x509"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/cawalch/go-yara/internal/pefixture"
)

func TestPECertificateFieldCacheParity(t *testing.T) {
	_, cert := pefixture.AuthenticodeBlob(pefixture.AuthenticodeOptions{IncludeChain: true})
	for _, certificate := range []*x509.Certificate{nil, cert, {}, {Raw: []byte{0x30, 0}, RawIssuer: []byte{1}, RawSubject: []byte{1}}} {
		image := &peImage{signatures: &peSignatureData{}}
		for _, field := range []string{"issuer", "subject", "serial", "thumbprint", "algorithm", "algorithm_oid", "version", "not_before", "not_after", "unknown"} {
			want := peCertificateField(certificate, field)
			for range 3 {
				got := image.certificateField(certificate, field)
				if got.Type != want.Type || got.String != want.String || got.Integer != want.Integer {
					t.Fatalf("%s: got %+v want %+v", field, got, want)
				}
			}
		}
		if allocs := testing.AllocsPerRun(100, func() {
			for _, field := range []string{"issuer", "subject", "serial", "thumbprint", "algorithm", "algorithm_oid"} {
				image.certificateField(certificate, field)
			}
		}); allocs != 0 {
			t.Fatalf("repeated defined/undefined fields allocated %.1f times", allocs)
		}
	}
	image := &peImage{signatures: &peSignatureData{}}
	image.certificateField(cert, "version")
	if image.signatures.certificateFields != nil {
		t.Fatal("scalar access allocated certificate cache")
	}
	image.certificateField(cert, "issuer")
	array := image.certificateArray([]*x509.Certificate{cert, cert})
	for _, element := range array.object.elements {
		element.object.field("issuer")
		element.object.field("subject")
	}
	if len(image.signatures.certificateFields) != 1 {
		t.Fatal("certificate aliases did not share a cache")
	}
	if allocs := testing.AllocsPerRun(100, func() { image.certificateField(cert, "issuer"); image.certificateField(cert, "subject") }); allocs != 0 {
		t.Fatalf("cached reads allocated %.1f times", allocs)
	}
}

func TestPECertificateCacheScannerReuse(t *testing.T) {
	p, err := NewCompiler().CompileSource(`import "pe" rule a {condition: pe.signatures[0].serial == "11"} rule b {condition: pe.signatures[0].serial == "22"}`)
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
	var inputs [][]byte
	for _, serial := range []int64{0x11, 0x22} {
		blob, _ := pefixture.AuthenticodeBlob(pefixture.AuthenticodeOptions{Serial: big.NewInt(serial)})
		inputs = append(inputs, pefixture.WithCertificates(pefixture.New(false), pefixture.CertificateRecord{Type: 2, Payload: blob}))
	}
	for _, program := range []*CompiledProgram{p, loaded} {
		s := program.NewScanner()
		for _, index := range []int{0, 1, 0, 1} {
			r, err := s.Scan(inputs[index])
			if err != nil {
				t.Fatal(err)
			}
			if r.RuleResults["a"] != (index == 0) || r.RuleResults["b"] != (index == 1) {
				t.Fatalf("stale certificate cache: %v", r.RuleResults)
			}
		}
		s.Close()
	}
}

func BenchmarkPECertificateFields(b *testing.B) {
	blob, _ := pefixture.AuthenticodeBlob(pefixture.AuthenticodeOptions{IncludeChain: true})
	data := pefixture.WithCertificates(pefixture.New(false), pefixture.CertificateRecord{Type: 2, Payload: blob})
	for _, rules := range []int{1, 32} {
		b.Run(fmt.Sprintf("rules=%d", rules), func(b *testing.B) {
			var source strings.Builder
			source.WriteString("import \"pe\"\n")
			for i := range rules {
				fmt.Fprintf(&source, `rule r%d {condition: defined pe.signatures[0].issuer and defined pe.signatures[0].subject and defined pe.signatures[0].serial and defined pe.signatures[0].thumbprint and defined pe.signatures[0].algorithm and defined pe.signatures[0].algorithm_oid}`, i)
			}
			p, err := NewCompiler().CompileSource(source.String())
			if err != nil {
				b.Fatal(err)
			}
			s := p.NewScanner()
			defer s.Close()
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				r, err := s.Scan(data)
				if err != nil || !r.RuleResults["r0"] {
					b.Fatalf("scan failed: %v", err)
				}
			}
		})
	}
}
