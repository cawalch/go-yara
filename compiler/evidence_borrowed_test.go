package compiler

import (
	"bytes"
	"fmt"
	"strings"
	"sync"
	"testing"
	"unsafe"
)

func TestBorrowedEvidence_DirectAliasingAndCapBounds(t *testing.T) {
	source := `rule credential_leak {
		strings:
			$a = /token=([a-z]+):([a-z]*)/ capture(name=1, secret=2, whole=0)
		evidence:
			pair = (name, secret) within 0 of secret
		condition:
			#a > 0
	}`

	p, err := NewCompiler().CompileSource(source)
	if err != nil {
		t.Fatal(err)
	}

	input := []byte("token=myuser:mysecretpassword!")
	scanner := p.NewScanner(WithEvidence(64), WithBorrowedEvidence(true))
	defer scanner.Close()

	res, err := scanner.Scan(input)
	if err != nil {
		t.Fatal(err)
	}

	findings := res.Evidence["credential_leak"]["pair"]
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	finding := findings[0]
	if finding.Status != EvidenceStatusReady {
		t.Fatalf("expected ready status, got %s", finding.Status)
	}

	secretCap := finding.Fields["secret"][0]
	nameCap := finding.Fields["name"][0]

	if string(secretCap.Data) != "mysecretpassword" {
		t.Fatalf("secret data mismatch: got %s", string(secretCap.Data))
	}
	if string(nameCap.Data) != "myuser" {
		t.Fatalf("name data mismatch: got %s", string(nameCap.Data))
	}

	// Verify direct pointer aliasing: Data must point directly inside input slice
	inputStart := uintptr(unsafe.Pointer(&input[0]))
	inputEnd := inputStart + uintptr(len(input))

	secretPtr := uintptr(unsafe.Pointer(&secretCap.Data[0]))
	if secretPtr < inputStart || secretPtr >= inputEnd {
		t.Fatal("secretCap.Data does not alias the input slice")
	}

	namePtr := uintptr(unsafe.Pointer(&nameCap.Data[0]))
	if namePtr < inputStart || namePtr >= inputEnd {
		t.Fatal("nameCap.Data does not alias the input slice")
	}

	// Verify exact capacity bounds (full slice expression [:len:len])
	// Appending to borrowed data MUST NOT overwrite adjacent input bytes
	if cap(nameCap.Data) != len(nameCap.Data) {
		t.Fatalf("nameCap.Data cap (%d) != len (%d); missing 3-index slice bounds", cap(nameCap.Data), len(nameCap.Data))
	}
	if cap(secretCap.Data) != len(secretCap.Data) {
		t.Fatalf("secretCap.Data cap (%d) != len (%d); missing 3-index slice bounds", cap(secretCap.Data), len(secretCap.Data))
	}

	// Append must allocate a new slice, leaving original input uncorrupted
	//nolint:gocritic // deliberately testing append to a new slice to verify slice isolation
	mutated := append(nameCap.Data, 'X')
	_ = mutated
	if !bytes.Equal(input, []byte("token=myuser:mysecretpassword!")) {
		t.Fatal("append to borrowed capture mutated input buffer")
	}
}

func TestBorrowedEvidence_ScannerReuseFluctuatingFindings(t *testing.T) {
	source := `rule multi_leak {
		strings:
			$a = /id=([0-9]+)/ capture(num=1)
		evidence:
			item = (num) within 0 of num
		condition:
			#a > 0
	}`

	p, err := NewCompiler().CompileSource(source)
	if err != nil {
		t.Fatal(err)
	}

	scanner := p.NewScanner(WithEvidence(64), WithBorrowedEvidence(true))
	defer scanner.Close()

	// Sequence of fluctuating match densities to test map/slice growth and resetting
	counts := []int{50, 0, 1000, 5, 200, 0, 500}
	for _, count := range counts {
		var input strings.Builder
		for i := 0; i < count; i++ {
			fmt.Fprintf(&input, "id=%04d\n", i)
		}
		res, err := scanner.Scan([]byte(input.String()))
		if err != nil {
			t.Fatalf("count=%d scan error: %v", count, err)
		}

		findings := res.Evidence["multi_leak"]["item"]
		if len(findings) != count {
			t.Fatalf("count=%d: expected %d findings, got %d", count, count, len(findings))
		}

		for i, f := range findings {
			expected := fmt.Sprintf("%04d", i)
			actual := string(f.Fields["num"][0].Data)
			if actual != expected {
				t.Fatalf("count=%d idx=%d: expected %s, got %s", count, i, expected, actual)
			}
		}
	}
}

func TestBorrowedEvidence_ConcurrentScanners(t *testing.T) {
	source := `rule thread_test {
		strings:
			$a = /val=([a-z0-9]+)/ capture(v=1)
		evidence:
			val = (v) within 0 of v
		condition:
			#a > 0
	}`

	p, err := NewCompiler().CompileSource(source)
	if err != nil {
		t.Fatal(err)
	}

	const goroutines = 8
	const iterations = 50

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			s := p.NewScanner(WithEvidence(64), WithBorrowedEvidence(true))
			defer s.Close()

			for it := 0; it < iterations; it++ {
				text := fmt.Sprintf("val=thread%diter%d\n", id, it)
				res, err := s.Scan([]byte(text))
				if err != nil {
					t.Errorf("worker %d iter %d scan error: %v", id, it, err)
					return
				}
				findings := res.Evidence["thread_test"]["val"]
				if len(findings) != 1 {
					t.Errorf("worker %d iter %d expected 1 finding, got %d", id, it, len(findings))
					return
				}
				expectedVal := fmt.Sprintf("thread%diter%d", id, it)
				gotVal := string(findings[0].Fields["v"][0].Data)
				if gotVal != expectedVal {
					t.Errorf("worker %d iter %d expected %s, got %s", id, it, expectedVal, gotVal)
					return
				}
			}
		}(g)
	}

	wg.Wait()
}
