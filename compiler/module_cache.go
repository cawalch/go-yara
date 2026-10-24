package compiler

import "math"

// Keep memoization bounded even when a rule calls a function on millions of
// distinct offsets. Once full, retain the first entries and evaluate misses.
// Keys use qualified names, since deserialized rules can assign different IDs
// to the same function. String arguments are deliberately not retained.
type moduleCallCache struct {
	entries [16]moduleCallCacheEntry
	count   int
}
type moduleCallCacheEntry struct {
	name   string
	args   [3]moduleCacheArgument
	argc   int
	result ModuleValue
}

type moduleCacheArgument struct {
	kind ModuleValueType
	bits uint64
}

func (cache *moduleCallCache) reset() {
	clear(cache.entries[:cache.count])
	cache.count = 0
}

func moduleCallKey(name string, args []ModuleValue) (moduleCallCacheEntry, bool) {
	key := moduleCallCacheEntry{name: name, argc: len(args)}
	if len(args) > len(key.args) {
		return key, false
	}
	for index, arg := range args {
		if arg.Type != ModuleInteger && arg.Type != ModuleFloat && arg.Type != ModuleBoolean {
			return key, false
		}
		key.args[index].kind = arg.Type
		switch arg.Type {
		case ModuleInteger:
			key.args[index].bits = uint64(arg.Integer)
		case ModuleFloat:
			key.args[index].bits = math.Float64bits(arg.Float)
		case ModuleBoolean:
			if arg.Boolean {
				key.args[index].bits = 1
			}
		}
	}
	return key, true
}

func (cache *moduleCallCache) lookup(key moduleCallCacheEntry) (ModuleValue, bool) {
	for index := 0; index < cache.count; index++ {
		entry := &cache.entries[index]
		if entry.name == key.name && entry.argc == key.argc && entry.args == key.args {
			return entry.result, true
		}
	}
	return ModuleValue{}, false
}

func (cache *moduleCallCache) put(key moduleCallCacheEntry, result ModuleValue) {
	if cache.count == len(cache.entries) {
		return
	}
	key.result = result
	cache.entries[cache.count] = key
	cache.count++
}
