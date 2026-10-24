package compiler

import (
	"errors"
	"fmt"
	"math"
	"reflect"
	"slices"
	"strings"
)

// WithModuleData binds a snapshot of a Go struct or string-keyed map to a module.
// Exported struct fields use their name or a `yara:"name"` tag. Binding errors
// are returned by scan methods. Missing fields and keys evaluate as undefined.
func WithModuleData(name string, data any) ScannerOption {
	return func(scanner *Scanner) {
		if err := scanner.SetModuleData(name, data); err != nil {
			scanner.moduleErr = err
		}
	}
}

// SetModuleData replaces one module's data with an owned, schema-checked snapshot.
// Like other scanner setters, it must not run concurrently with a scan.
func (s *Scanner) SetModuleData(name string, data any) error {
	if s == nil || s.program == nil {
		return errors.New("module data requires a compiled program")
	}
	schema := s.program.moduleSchemas[name]
	if schema == nil {
		return fmt.Errorf("unknown structured module %q", name)
	}
	value, err := bindModuleValue(ModuleField{Kind: ModuleStruct, Struct: schema}, reflect.ValueOf(data), 0)
	if err != nil {
		return fmt.Errorf("module %s: %w", name, err)
	}
	if s.moduleData == nil {
		s.moduleData = map[string]ModuleValue{}
	}
	// Discard references to prior snapshots retained in VM scratch storage.
	if s.interp != nil {
		clear(s.interp.stack[:cap(s.interp.stack)])
		clear(s.interp.iterators[:cap(s.interp.iterators)])
		clear(s.interp.memory[:])
	}
	s.moduleData[name] = value
	return nil
}

func bindModuleValue(field ModuleField, data reflect.Value, depth int) (ModuleValue, error) {
	if depth > 32 {
		return ModuleValue{}, errors.New("module data exceeds 32 levels")
	}
	if field.Constant != nil {
		return *field.Constant, nil
	}
	for data.IsValid() && (data.Kind() == reflect.Pointer || data.Kind() == reflect.Interface) {
		if data.IsNil() {
			return ModuleValue{}, nil
		}
		depth++
		if depth > 32 {
			return ModuleValue{}, errors.New("module data exceeds 32 levels")
		}
		data = data.Elem()
	}
	if !data.IsValid() {
		return ModuleValue{}, nil
	}
	if data.CanInterface() {
		if value, ok := data.Interface().(ModuleValue); ok && (value.Type == ModuleUndefined || value.Type == field.Kind && field.Kind <= ModuleBoolean) {
			return value, nil
		}
	}
	switch field.Kind {
	case ModuleInteger:
		if data.CanInt() {
			return IntegerValue(data.Int()), nil
		}
		if data.CanUint() && data.Uint() <= math.MaxInt64 {
			//checkednarrow:ignore value is bounded by MaxInt64 above
			return IntegerValue(int64(data.Uint())), nil
		}
	case ModuleFloat:
		if data.Kind() == reflect.Float32 || data.Kind() == reflect.Float64 {
			return FloatValue(data.Float()), nil
		}
	case ModuleString:
		if data.Kind() == reflect.String {
			return StringValue(data.String()), nil
		}
	case ModuleBoolean:
		if data.Kind() == reflect.Bool {
			return BooleanValue(data.Bool()), nil
		}
	case ModuleStruct:
		return bindModuleStruct(field.Struct, data, depth)
	case ModuleArray:
		if data.Kind() == reflect.Slice || data.Kind() == reflect.Array {
			return bindModuleArray(*field.Element, data, depth)
		}
	case ModuleDictionary:
		if data.Kind() == reflect.Map && data.Type().Key().Kind() == reflect.String {
			return bindModuleDictionary(*field.Element, data, depth)
		}
	}
	return ModuleValue{}, fmt.Errorf("value %s does not match module kind %d", data.Type(), field.Kind)
}

func bindModuleStruct(schema *ModuleSchema, data reflect.Value, depth int) (ModuleValue, error) {
	if data.Kind() != reflect.Struct && (data.Kind() != reflect.Map || data.Type().Key().Kind() != reflect.String) {
		return ModuleValue{}, errors.New("structure requires a Go struct or string-keyed map")
	}
	object := &moduleObject{kind: ModuleStruct, fields: make(map[string]ModuleValue, len(schema.Fields))}
	for name, field := range schema.Fields {
		value, err := bindModuleValue(field, moduleStructField(data, name), depth+1)
		if err != nil {
			return ModuleValue{}, fmt.Errorf("field %s: %w", name, err)
		}
		object.fields[name] = value
	}
	return ModuleValue{Type: ModuleStruct, object: object}, nil
}

func moduleStructField(data reflect.Value, name string) reflect.Value {
	if data.Kind() == reflect.Map {
		return data.MapIndex(reflect.ValueOf(name).Convert(data.Type().Key()))
	}
	for index := 0; index < data.NumField(); index++ {
		field := data.Type().Field(index)
		if field.PkgPath != "" {
			continue
		}
		tag, tagged := field.Tag.Lookup("yara")
		if tag == "-" {
			continue
		}
		if tagged && tag == name || !tagged && strings.EqualFold(field.Name, name) {
			return data.Field(index)
		}
	}
	return reflect.Value{}
}

func bindModuleArray(element ModuleField, data reflect.Value, depth int) (ModuleValue, error) {
	object := &moduleObject{kind: ModuleArray, elements: make([]ModuleValue, data.Len())}
	for index := range object.elements {
		value, err := bindModuleValue(element, data.Index(index), depth+1)
		if err != nil {
			return ModuleValue{}, fmt.Errorf("index %d: %w", index, err)
		}
		object.elements[index] = value
	}
	return ModuleValue{Type: ModuleArray, object: object}, nil
}

func bindModuleDictionary(element ModuleField, data reflect.Value, depth int) (ModuleValue, error) {
	object := &moduleObject{kind: ModuleDictionary, fields: make(map[string]ModuleValue, data.Len())}
	iter := data.MapRange()
	for iter.Next() {
		key := iter.Key().String()
		value, err := bindModuleValue(element, iter.Value(), depth+1)
		if err != nil {
			return ModuleValue{}, fmt.Errorf("key %q: %w", key, err)
		}
		object.fields[key] = value
		object.keys = append(object.keys, key)
	}
	slices.Sort(object.keys)
	return ModuleValue{Type: ModuleDictionary, object: object}, nil
}
