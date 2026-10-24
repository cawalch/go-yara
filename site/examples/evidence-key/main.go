package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"

	"github.com/cawalch/go-yara/compiler"
)

const rules = `
rule private_key_candidate {
    strings:
        $pem = /-----BEGIN PRIVATE KEY-----\r?\n[A-Za-z0-9+\/=\r\n]+-----END PRIVATE KEY-----/
            capture(secret = 0)
    evidence:
        key = (secret) within 0 of secret
    condition:
        $pem
}`

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	// Generate a disposable key in memory; never print or write it to disk.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	program, err := compiler.NewCompiler().CompileSourceWithContext(context.Background(), rules)
	if err != nil {
		return err
	}
	scanner := program.NewScanner(compiler.WithEvidence(8 * 1024))
	defer scanner.Close()
	for _, sample := range []struct {
		name string
		der  []byte
	}{
		{"generated key", der},
		{"invalid DER", []byte("not a private key")},
	} {
		input := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: sample.der})
		result, err := scanner.Scan(input)
		if err != nil {
			return err
		}
		findings := result.Evidence["private_key_candidate"]["key"]
		if !result.RuleResults["private_key_candidate"] || len(findings) != 1 {
			return fmt.Errorf("%s: expected one key candidate", sample.name)
		}
		finding := findings[0]
		captures := finding.Fields["secret"]
		if finding.Status != compiler.EvidenceStatusReady || len(captures) != 1 || captures[0].DataTruncated {
			return fmt.Errorf("%s: incomplete key capture", sample.name)
		}
		block, rest := pem.Decode(captures[0].Data)
		if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
			return fmt.Errorf("%s: expected one complete PEM block", sample.name)
		}
		_, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes)
		fmt.Printf("%s: %s; PKCS#8 parsed=%t\n", sample.name, finding.Status, parseErr == nil)
	}
	return nil
}
