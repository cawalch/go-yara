package operandcontract_test

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/cawalch/go-yara/internal/analyzers/operandcontract"
)

func TestAnalyzer(t *testing.T) {
	analysistest.Run(
		t,
		analysistest.TestData(),
		operandcontract.Analyzer,
		"compiler",
	)
}
