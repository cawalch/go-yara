package compiler

import "testing"

func BenchmarkLiteralPrefilterFastReject(b *testing.B) {
	program, err := NewCompiler().CompileSource(`
rule structured_secret {
    strings:
        $gate = "api_key"
        $value = "secret_value"
    condition:
        all of them
}
`)
	if err != nil {
		b.Fatalf("CompileSource() error = %v", err)
	}
	inputs := []struct {
		name string
		data []byte
	}{
		{name: "reject", data: []byte(`{"level":"info","message":"request completed","status":200}`)},
		{name: "gate_pass", data: []byte(`{"level":"debug","field":"api_key","status":"redacted"}`)},
		{name: "match", data: []byte(`{"level":"warn","field":"api_key","value":"secret_value"}`)},
	}
	for _, input := range inputs {
		b.Run(input.name, func(b *testing.B) {
			benchmarkScannerMatches(b, program, input.data)
		})
	}

	reject := inputs[0].data
	b.Run("reject_parallel", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(reject)))
		b.RunParallel(func(pb *testing.PB) {
			scanner := NewScanner(program)
			defer scanner.Close()
			if _, err := scanner.Matches(reject); err != nil {
				b.Error(err)
				return
			}
			for pb.Next() {
				if _, err := scanner.Matches(reject); err != nil {
					b.Error(err)
					return
				}
			}
		})
	})

	alternationProgram, err := NewCompiler().CompileSource(`
rule contact {
    strings:
        $value = /"(phone|phone_number|mobile)":"[0-9]{7}"/
    condition:
        $value
}
`)
	if err != nil {
		b.Fatalf("CompileSource() alternation error = %v", err)
	}
	b.Run("alternation_reject", func(b *testing.B) {
		benchmarkScannerMatches(b, alternationProgram, reject)
	})

	largeAlternationProgram, err := NewCompiler().CompileSource(`
rule pii_dob_in_assignment {
    strings:
        $value = /"(date_of_birth|birth_date|birthdate|dateOfBirth|birthday|dob)":"[0-9]{4}"/
    condition:
        $value
}
`)
	if err != nil {
		b.Fatalf("CompileSource() large alternation error = %v", err)
	}
	b.Run("large_alternation_reject", func(b *testing.B) {
		benchmarkScannerMatches(b, largeAlternationProgram, reject)
	})
	b.Run("large_alternation_match", func(b *testing.B) {
		benchmarkScannerMatches(
			b,
			largeAlternationProgram,
			[]byte(`{"date_of_birth":"1984"}`),
		)
	})

	caseClassProgram, err := NewCompiler().CompileSource(`
rule credential {
    strings:
        $value = /"[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]":"(REDACTED|null)"/
    condition:
        $value
}
`)
	if err != nil {
		b.Fatalf("CompileSource() case-class error = %v", err)
	}
	b.Run("case_class_reject", func(b *testing.B) {
		benchmarkScannerMatches(b, caseClassProgram, reject)
	})
}

func benchmarkScannerMatches(b *testing.B, program *CompiledProgram, data []byte) {
	b.Helper()
	scanner := NewScanner(program)
	defer scanner.Close()
	if _, err := scanner.Matches(data); err != nil {
		b.Fatalf("warm-up Matches() error = %v", err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for b.Loop() {
		if _, err := scanner.Matches(data); err != nil {
			b.Fatal(err)
		}
	}
}
