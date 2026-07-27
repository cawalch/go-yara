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
			scanner := NewScanner(program)
			defer scanner.Close()
			if _, err := scanner.Matches(input.data); err != nil {
				b.Fatalf("warm-up Matches() error = %v", err)
			}
			b.ReportAllocs()
			b.SetBytes(int64(len(input.data)))
			b.ResetTimer()
			for b.Loop() {
				if _, err := scanner.Matches(input.data); err != nil {
					b.Fatal(err)
				}
			}
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
}
