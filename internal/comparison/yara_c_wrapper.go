// Package comparison provides CGO bindings to the C YARA library for performance comparison.
package comparison

/*
#cgo CFLAGS: -I${SRCDIR}/../../yara/libyara/include
#cgo LDFLAGS: -L${SRCDIR}/../../yara/.libs -lyara -lm

#include <stdlib.h>
#include <yara.h>

// Wrapper function to compile YARA rules from a string
int compile_yara_rules(const char* rules_string, YR_RULES** rules) {
    YR_COMPILER* compiler = NULL;
    int result;
    
    result = yr_compiler_create(&compiler);
    if (result != ERROR_SUCCESS) {
        return result;
    }
    
    result = yr_compiler_add_string(compiler, rules_string, NULL);
    if (result != 0) {
        yr_compiler_destroy(compiler);
        return result;
    }
    
    result = yr_compiler_get_rules(compiler, rules);
    yr_compiler_destroy(compiler);
    
    return result;
}
*/
import "C"
import (
	"fmt"
	"runtime"
	"unsafe"
)

// YaraCompiler wraps the C YARA compiler for benchmarking.
type YaraCompiler struct {
	initialized bool
}

// NewYaraCompiler creates a new YARA C compiler wrapper.
func NewYaraCompiler() (*YaraCompiler, error) {
	result := C.yr_initialize()
	if result != C.ERROR_SUCCESS {
		return nil, fmt.Errorf("failed to initialize YARA: %d", result)
	}
	
	yc := &YaraCompiler{initialized: true}
	runtime.SetFinalizer(yc, func(yc *YaraCompiler) {
		if yc.initialized {
			C.yr_finalize()
		}
	})
	
	return yc, nil
}

// CompileString compiles YARA rules from a string and returns success/failure.
// This measures the full compilation pipeline including lexing and parsing.
func (yc *YaraCompiler) CompileString(rulesString string) error {
	if !yc.initialized {
		return fmt.Errorf("YARA not initialized")
	}
	
	cRulesString := C.CString(rulesString)
	defer C.free(unsafe.Pointer(cRulesString))
	
	var rules *C.YR_RULES
	result := C.compile_yara_rules(cRulesString, &rules)
	
	if result == C.ERROR_SUCCESS && rules != nil {
		C.yr_rules_destroy(rules)
		return nil
	}
	
	return fmt.Errorf("compilation failed: %d", result)
}

// Close finalizes the YARA library.
func (yc *YaraCompiler) Close() {
	if yc.initialized {
		C.yr_finalize()
		yc.initialized = false
	}
}

