package goblimit

import (
	"errors"
	"math"
	"reflect"
	"strconv"
)

const (
	firstUserID        = 64
	maxTypes           = 512
	maxDefinitionBytes = 32 << 10
	maxDepth           = 256
)

var errBudget = errors.New("compiled artifact exceeds decoded collection budget")

// Check inspects one complete artifact value. It charges slice backing arrays,
// map entries, pointer targets and string/byte payloads using the destination
// types, before the standard decoder can allocate them. The budget measures
// logical decoded storage, rather than allocator size classes or peak RSS.
func Check(data []byte, root reflect.Type, budget int) (int, error) {
	if budget < 0 {
		return 0, errBudget
	}
	c := wireCursor{data: data}
	start := len(c.data)
	s := schema{types: make(map[int]*wireType), nodes: make(map[binding]*node)}
	for len(c.data) > 0 {
		msg := c.take(c.uint())
		if c.err != nil {
			return 0, c.err
		}
		frame := wireCursor{data: msg}
		raw := frame.uint()
		if raw > 2*math.MaxInt32 || frame.err != nil {
			return 0, errWire
		}
		if raw&1 != 0 {
			id := int(raw>>1) + 1
			if id < firstUserID || len(s.types) >= maxTypes || s.types[id] != nil || len(msg) > maxDefinitionBytes {
				return 0, errWire
			}
			t, err := definition(&frame, id)
			if err != nil {
				return 0, err
			}
			s.types[id] = t
			continue
		}
		id := int(raw >> 1)
		if s.types[id] == nil || s.types[id].kind != structKind {
			return 0, errWire
		}
		plan, err := s.bind(binding{id: id, dest: root})
		if err != nil {
			return 0, err
		}
		state := valueBudget{wireCursor: frame, left: uint64(budget)}
		state.walk(plan, 0)
		if state.err != nil {
			return 0, state.err
		}
		if len(state.data) != 0 {
			return 0, errWire
		}
		return start - len(c.data), nil
	}
	return 0, errWire
}

type binding struct {
	id       int
	dest     reflect.Type
	maxCount uint64
}

type schema struct {
	types map[int]*wireType
	nodes map[binding]*node
}

type node struct {
	kind                       uint64
	length, maxCount           uint64
	elementBytes, pointerBytes uint64
	elem, key                  *node
	fields                     []*node
}

// Scalar wire IDs use a separate range from the four compound kinds.
const scalarBase = 16

func (s *schema) bind(b binding) (*node, error) {
	id, dest := b.id, b.dest
	if n := s.nodes[b]; n != nil {
		return n, nil
	}
	if len(s.nodes) >= 4*maxTypes {
		return nil, errWire
	}
	n := &node{maxCount: b.maxCount}
	s.nodes[b] = n // allow recursive structs such as nested hex alternatives
	for dest != nil && dest.Kind() == reflect.Pointer {
		dest = dest.Elem()
		n.pointerBytes += uint64(dest.Size())
	}
	if id >= 1 && id <= 7 {
		n.kind = scalarBase + uint64(id)
		// encoding/gob performs the scalar type compatibility check.
		return n, nil
	}
	t := s.types[id]
	if t == nil {
		return nil, errWire
	}
	n.kind, n.length = t.kind, t.length
	var child, key reflect.Type
	switch t.kind {
	case structKind:
		if dest != nil && dest.Kind() != reflect.Struct {
			return nil, errWire
		}
		n.fields = make([]*node, len(t.fields))
		for i, f := range t.fields {
			child, err := fieldBinding(f, dest)
			if err != nil {
				return nil, err
			}
			sub, err := s.bind(child)
			if err != nil {
				return nil, err
			}
			n.fields[i] = sub
		}
		return n, nil
	case mapKind:
		if dest != nil {
			if dest.Kind() != reflect.Map {
				return nil, errWire
			}
			key, child = dest.Key(), dest.Elem()
			n.elementBytes = uint64(key.Size()+child.Size()) + 16
		}
		k, err := s.bind(binding{id: t.key, dest: key})
		if err != nil {
			return nil, err
		}
		n.key = k
	case arrayKind, sliceKind:
		if dest != nil {
			if t.kind == arrayKind && (dest.Kind() != reflect.Array || uint64(dest.Len()) != t.length) {
				return nil, errWire
			}
			if t.kind == sliceKind && dest.Kind() != reflect.Slice {
				return nil, errWire
			}
			child = dest.Elem()
			if t.kind == sliceKind {
				n.elementBytes = uint64(child.Size())
			}
		}
	}
	elem, err := s.bind(binding{id: t.elem, dest: child})
	n.elem = elem
	return n, err
}

// A field missing from the destination is skipped by encoding/gob. Its wire
// structure must still be checked to keep the next field aligned.
func fieldBinding(f fieldDef, dest reflect.Type) (binding, error) {
	b := binding{id: f.id}
	if dest == nil {
		return b, nil
	}
	field, ok := dest.FieldByName(f.name)
	if !ok || !field.IsExported() {
		return b, nil
	}
	b.dest = field.Type
	if tag := field.Tag.Get("gobmax"); tag != "" {
		var err error
		b.maxCount, err = strconv.ParseUint(tag, 10, 64)
		return b, err
	}
	return b, nil
}

type valueBudget struct {
	wireCursor
	left uint64
}

func (v *valueBudget) charge(count, size uint64) bool {
	if size != 0 && count > v.left/size {
		v.err = errBudget
		return false
	}
	v.left -= count * size
	return true
}

func (v *valueBudget) walk(n *node, depth int) {
	if depth > maxDepth {
		v.err = errWire
		return
	}
	if !v.charge(1, n.pointerBytes) {
		return
	}
	switch n.kind {
	case scalarBase + 1, scalarBase + 2, scalarBase + 3, scalarBase + 4:
		v.uint()
	case scalarBase + 7:
		v.uint()
		v.uint()
	case scalarBase + 5, scalarBase + 6:
		count := v.uint()
		if n.maxCount != 0 && count > n.maxCount {
			v.err = errBudget
			return
		}
		if v.charge(count, 1) {
			v.take(count)
		}
	case structKind:
		next := 0
		for delta := v.uint(); delta != 0 && v.err == nil; delta = v.uint() {
			if delta > uint64(len(n.fields)-next) {
				v.err = errWire
				return
			}
			next += int(delta)
			v.walk(n.fields[next-1], depth+1)
			if v.err != nil {
				return
			}
		}
	case sliceKind, arrayKind, mapKind:
		count := v.uint()
		if count > uint64(len(v.data)) || n.kind == arrayKind && count != n.length {
			v.err = errWire
			return
		}
		if n.maxCount != 0 && count > n.maxCount {
			v.err = errBudget
			return
		}
		if !v.charge(count, n.elementBytes) {
			return
		}
		for ; count > 0 && v.err == nil; count-- {
			if n.key != nil {
				v.walk(n.key, depth+1)
				if v.err != nil {
					return
				}
			}
			v.walk(n.elem, depth+1)
		}
	}
}
