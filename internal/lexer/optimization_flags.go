package lexer

import "os"

// Feature flags for experimental optimizations
// These are cached at initialization to avoid repeated os.Getenv calls in hot paths

// Cached optimization flags - initialized once at package init
var (
	poolingOptimizationEnabled bool
	stringInterningEnabled     bool
)

func init() {
	// Initialize flags from environment variables at startup
	// This avoids expensive os.Getenv calls in the hot path
	poolingOptimizationEnabled = readBoolEnv("YARA_OPT_POOLING", true)
	stringInterningEnabled = readBoolEnv("YARA_OPT_INTERNING", true)
}

// readBoolEnv reads a boolean environment variable with a default value
// Returns true if env var is "1", "true", or "enabled"
// Returns false if env var is "0", "false", or "disabled"
// Returns defaultValue for any other value or if not set
func readBoolEnv(envVar string, defaultValue bool) bool {
	value := os.Getenv(envVar)
	if value == "" {
		return defaultValue
	}

	switch value {
	case "1", "true", "enabled":
		return true
	case "0", "false", "disabled":
		return false
	default:
		return defaultValue
	}
}

// isPoolingOptimizationEnabled returns whether string builder pooling is enabled
// This is cached at initialization time to avoid os.Getenv calls in hot paths
func isPoolingOptimizationEnabled() bool {
	return poolingOptimizationEnabled
}

// isStringInterningEnabled returns whether string interning is enabled
// This is cached at initialization time to avoid os.Getenv calls in hot paths
func isStringInterningEnabled() bool {
	return stringInterningEnabled
}
