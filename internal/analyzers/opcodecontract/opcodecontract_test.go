package opcodecontract_test

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/cawalch/go-yara/internal/analyzers/opcodecontract"
)

func TestAnalyzer(t *testing.T) {
	analysistest.Run(
		t,
		analysistest.TestData(),
		opcodecontract.Analyzer,
		"compiler",
	)
}
