// Command go-yara-analyzers runs repository-specific static analysis checks.
package main

import (
	"golang.org/x/tools/go/analysis/multichecker"

	"github.com/cawalch/go-yara/internal/analyzers/checkednarrow"
	"github.com/cawalch/go-yara/internal/analyzers/opcodecontract"
	"github.com/cawalch/go-yara/internal/analyzers/operandcontract"
)

func main() {
	multichecker.Main(
		checkednarrow.Analyzer,
		opcodecontract.Analyzer,
		operandcontract.Analyzer,
	)
}
