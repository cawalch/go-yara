package checkednarrow_test

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"github.com/cawalch/go-yara/internal/analyzers/checkednarrow"
)

func TestAnalyzer(t *testing.T) {
	analysistest.Run(
		t,
		analysistest.TestData(),
		checkednarrow.Analyzer,
		"checked",
	)
}
