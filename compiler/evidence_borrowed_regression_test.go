package compiler

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cawalch/go-yara/utils/fs"
)

func TestBorrowedEvidenceScanFileDoesNotUseAfterMunmap(t *testing.T) {
	source := `
rule FileSecret {
	strings:
		$uri = /token=([A-Za-z0-9]+)/ capture(secret = 1)
	evidence:
		cred = (secret) within 0 of secret
	condition:
		$uri
}`
	c := NewCompiler()
	program, err := c.CompileSourceWithContext(context.Background(), source)
	require.NoError(t, err)

	// Exceed fs.MinMmapFileSize so ScanFile would previously mmap and unmap before returning.
	payload := make([]byte, fs.MinMmapFileSize+4096)
	for i := range payload {
		payload[i] = ' '
	}
	copy(payload[fs.MinMmapFileSize:], []byte("token=SuperSecretValue12345"))

	path := filepath.Join(t.TempDir(), "large.bin")
	require.NoError(t, os.WriteFile(path, payload, 0o600))

	scanner := program.NewScanner(
		WithEvidence(1024),
		WithBorrowedEvidence(true),
	)
	defer scanner.Close()

	result, err := scanner.ScanFile(path)
	require.NoError(t, err)
	require.Len(t, result.MatchedRules, 1)

	findings := result.Evidence["FileSecret"]["cred"]
	require.Len(t, findings, 1)
	require.Equal(t, []byte("SuperSecretValue12345"), findings[0].Anchor.Data)
	require.Equal(t, []byte("SuperSecretValue12345"), findings[0].Fields["secret"][0].Data)
	require.Equal(t, []byte("SuperSecretValue12345"), result.Matches["FileSecret"]["$uri"][0].Captures[0].Data)
}

func TestBorrowedEvidencePreservesMultiplePlansAndRules(t *testing.T) {
	source := `
rule MultiPlanRule {
	strings:
		$a = /alpha:([a-z0-9]+)/ capture(a_val = 1)
		$b = /beta:([a-z0-9]+)/ capture(b_val = 1)
	evidence:
		plan_a = (a_val) within 0 of a_val
		plan_b = (b_val) within 0 of b_val
	condition:
		$a and $b
}

rule SecondRule {
	strings:
		$g = /gamma:([a-z0-9]+)/ capture(g_val = 1)
	evidence:
		plan_g = (g_val) within 0 of g_val
	condition:
		$g
}`
	c := NewCompiler()
	program, err := c.CompileSourceWithContext(context.Background(), source)
	require.NoError(t, err)

	scanner := program.NewScanner(
		WithEvidence(1024),
		WithBorrowedEvidence(true),
	)
	defer scanner.Close()

	input := []byte("alpha:first111 beta:second222 gamma:third333")

	// Run twice to exercise both cold slab allocation and warm slab reuse.
	for iter := range 2 {
		result, err := scanner.Scan(input)
		require.NoError(t, err, "iter %d", iter)
		require.Len(t, result.MatchedRules, 2, "iter %d", iter)

		planA := result.Evidence["MultiPlanRule"]["plan_a"]
		require.Len(t, planA, 1, "iter %d", iter)
		require.Equal(t, "a_val", planA[0].Fields["a_val"][0].Name, "iter %d", iter)
		require.Equal(t, []byte("first111"), planA[0].Fields["a_val"][0].Data, "iter %d", iter)

		planB := result.Evidence["MultiPlanRule"]["plan_b"]
		require.Len(t, planB, 1, "iter %d", iter)
		require.Equal(t, "b_val", planB[0].Fields["b_val"][0].Name, "iter %d", iter)
		require.Equal(t, []byte("second222"), planB[0].Fields["b_val"][0].Data, "iter %d", iter)

		planG := result.Evidence["SecondRule"]["plan_g"]
		require.Len(t, planG, 1, "iter %d", iter)
		require.Equal(t, "g_val", planG[0].Fields["g_val"][0].Name, "iter %d", iter)
		require.Equal(t, []byte("third333"), planG[0].Fields["g_val"][0].Data, "iter %d", iter)
	}
}

func TestAppendEvidenceJSONEscapesInvalidUTF8(t *testing.T) {
	finding := EvidenceFinding{
		Anchor: Capture{
			Name:    "bad\xffname",
			Pattern: "$p",
			Data:    []byte("ok"),
		},
		Status: EvidenceStatusReady,
		Fields: map[string][]Capture{
			"k\xfe": {{Name: "bad\xffname", Pattern: "$p", Data: []byte("ok")}},
		},
	}
	encoded := AppendEvidenceJSON(nil, map[string][]EvidenceFinding{
		"plan\x80": {finding},
	})
	require.True(t, json.Valid(encoded), "encoded JSON must be valid: %s", string(encoded))
	require.True(t, bytes.Contains(encoded, []byte(`\ufffd`)), "invalid UTF-8 should be replaced with \\ufffd: %s", string(encoded))
}
