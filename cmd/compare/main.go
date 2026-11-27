// Command compare compares rule matches on the same labeled inputs.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/cawalch/go-yara/internal/rulecompare"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	err := rulecompare.RunCLI(ctx, os.Args[1:], os.Stdout)
	stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(rulecompare.ExitCode(err))
	}
}
