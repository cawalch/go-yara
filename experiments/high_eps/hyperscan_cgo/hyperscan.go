//go:build hyperscan

package hyperscan_cgo

/*
#cgo LDFLAGS: -lhs

#include <hs/hs.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  hs_database_t *database;
  hs_scratch_t *scratch;
} tournament_engine;

static int stop_on_match(unsigned int id, unsigned long long from,
                         unsigned long long to, unsigned int flags,
                         void *context) {
  (void)id;
  (void)from;
  (void)to;
  (void)flags;
  *((int *)context) = 1;
  return 1;
}

static tournament_engine *tournament_engine_new(unsigned int rule_count) {
  tournament_engine *engine = calloc(1, sizeof(*engine));
  char **storage = calloc(rule_count, sizeof(*storage));
  const char **expressions = calloc(rule_count, sizeof(*expressions));
  unsigned int *flags = calloc(rule_count, sizeof(*flags));
  unsigned int *ids = calloc(rule_count, sizeof(*ids));
  if (engine == NULL || storage == NULL || expressions == NULL ||
      flags == NULL || ids == NULL) {
    goto fail;
  }
  for (unsigned int index = 0; index < rule_count; ++index) {
    storage[index] = malloc(64);
    if (storage[index] == NULL) {
      goto fail;
    }
    snprintf(storage[index], 64, "sig_%05u=[A-Z]{2}[0-9]{6}", index);
    expressions[index] = storage[index];
    flags[index] = HS_FLAG_SINGLEMATCH;
    ids[index] = index;
  }

  hs_compile_error_t *compile_error = NULL;
  if (hs_compile_multi(expressions, flags, ids, rule_count, HS_MODE_BLOCK,
                       NULL, &engine->database, &compile_error) != HS_SUCCESS) {
    if (compile_error != NULL) {
      fprintf(stderr, "Hyperscan compile failed at %d: %s\n",
              compile_error->expression, compile_error->message);
      hs_free_compile_error(compile_error);
    }
    goto fail;
  }
  if (hs_alloc_scratch(engine->database, &engine->scratch) != HS_SUCCESS) {
    goto fail;
  }

  for (unsigned int index = 0; index < rule_count; ++index) {
    free(storage[index]);
  }
  free(storage);
  free(expressions);
  free(flags);
  free(ids);
  return engine;

fail:
  if (storage != NULL) {
    for (unsigned int index = 0; index < rule_count; ++index) {
      free(storage[index]);
    }
  }
  free(storage);
  free(expressions);
  free(flags);
  free(ids);
  if (engine != NULL) {
    if (engine->scratch != NULL) {
      hs_free_scratch(engine->scratch);
    }
    if (engine->database != NULL) {
      hs_free_database(engine->database);
    }
    free(engine);
  }
  return NULL;
}

static int tournament_engine_scan(tournament_engine *engine,
                                  const char *data, unsigned int length) {
  int matched = 0;
  const hs_error_t result = hs_scan(engine->database, data, length, 0,
                                    engine->scratch, stop_on_match, &matched);
  if (result != HS_SUCCESS && result != HS_SCAN_TERMINATED) {
    return -1;
  }
  return matched;
}

static void tournament_engine_free(tournament_engine *engine) {
  if (engine == NULL) {
    return;
  }
  hs_free_scratch(engine->scratch);
  hs_free_database(engine->database);
  free(engine);
}
*/
import "C"

import (
	"fmt"
	"unsafe"
)

type engine struct {
	value *C.tournament_engine
}

func newEngine(ruleCount int) (*engine, error) {
	value := C.tournament_engine_new(C.uint(ruleCount))
	if value == nil {
		return nil, fmt.Errorf("compile %d Hyperscan expressions", ruleCount)
	}
	return &engine{value: value}, nil
}

func (e *engine) close() {
	if e != nil && e.value != nil {
		C.tournament_engine_free(e.value)
		e.value = nil
	}
}

func (e *engine) matches(data []byte) (bool, error) {
	if len(data) == 0 {
		return false, nil
	}
	result := C.tournament_engine_scan(
		e.value,
		(*C.char)(unsafe.Pointer(unsafe.SliceData(data))),
		C.uint(len(data)),
	)
	if result < 0 {
		return false, fmt.Errorf("Hyperscan block scan failed: %d", result)
	}
	return result != 0, nil
}
