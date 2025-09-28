package lexer

import "os"

// Feature flags for experimental optimizations
// These can be controlled via build tags or environment variables

// isOptimizationEnabled checks if a specific optimization is enabled
func isOptimizationEnabled(flagName string) bool {
	// Check environment variable first
	envVar := "YARA_OPT_" + flagName
	if value := os.Getenv(envVar); value != "" {
		return value == "1" || value == "true" || value == "enabled"
	}

	// Default to disabled for safety
	return false
}

// Specific optimization flags
func isPoolingOptimizationEnabled() bool {
	return isOptimizationEnabled("POOLING")
}

func isStringInterningEnabled() bool {
	return isOptimizationEnabled("INTERNING")
}
