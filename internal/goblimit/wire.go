// Package goblimit checks the collection allocation budget of a compiled
// artifact before encoding/gob decodes it. Artifacts use structs, maps, arrays,
// slices and scalar fields from the documented gob wire format.
package goblimit

import (
	"bytes"
	"errors"

	"io"
	"math"
)

var errWire = errors.New("invalid compiled artifact gob encoding")

// wireCursor fails closed. After an incomplete integer or byte string all
// subsequent reads return zero, including the struct field terminator.
type wireCursor struct {
	data []byte
	err  error
}

func (c *wireCursor) take(n uint64) []byte {
	if n > uint64(len(c.data)) {
		c.err = io.ErrUnexpectedEOF
		c.data = nil
		return nil
	}
	v := c.data[:n]
	c.data = c.data[n:]
	return v
}

func (c *wireCursor) uint() uint64 {
	if len(c.data) == 0 {
		c.err = io.ErrUnexpectedEOF
		return 0
	}
	b := c.data[0]
	c.data = c.data[1:]
	if b < 128 {
		return uint64(b)
	}
	width := 256 - int(b)
	if width > 8 {
		c.err = errWire
		c.data = nil
		return 0
	}
	var v uint64
	for _, b := range c.take(uint64(width)) {
		v = v<<8 | uint64(b)
	}
	return v
}

func (c *wireCursor) typeID() int {
	v := c.uint()
	if v == 0 || v&1 != 0 || v>>1 > math.MaxInt32 {
		c.err = errWire
		return 0
	}
	return int(v >> 1)
}

type fieldDef struct {
	name string
	id   int
}

type wireType struct {
	kind      uint64
	elem, key int
	length    uint64
	fields    []fieldDef
}

const (
	arrayKind  = 1
	sliceKind  = 2
	structKind = 3
	mapKind    = 4
)

// definition reads the standard wireType descriptor. Each artifact frame
// carries one definition or one top-level value. CommonType.Name is optional
// for unnamed types. Type references can point to later definitions.
func definition(c *wireCursor, id int) (*wireType, error) {
	t := &wireType{kind: c.uint()}
	if c.uint() != 1 {
		return nil, errWire
	}
	field := c.uint()
	if field == 1 {
		c.take(c.uint())
		if c.uint() != 1 {
			return nil, errWire
		}
		field = 2
	}
	if field != 2 || c.typeID() != id || c.uint() != 0 {
		return nil, errWire
	}
	next := c.uint()
	switch t.kind {
	case structKind:
		if next == 0 {
			break
		}

		if next != 1 {
			return nil, errWire
		}
		n := c.uint()
		if n > 256 || n > uint64(len(c.data)) {
			return nil, errWire
		}
		t.fields = make([]fieldDef, n)
		for i := range t.fields {
			if c.uint() != 1 {
				return nil, errWire
			}
			name := c.take(c.uint())
			if len(name) == 0 || c.uint() != 1 {
				return nil, errWire
			}
			t.fields[i] = fieldDef{string(name), c.typeID()}
			if c.uint() != 0 {
				return nil, errWire
			}
		}
		next = c.uint()

	case mapKind:
		if next != 1 {
			return nil, errWire
		}
		t.key = c.typeID()
		if c.uint() != 1 {
			return nil, errWire
		}
		t.elem = c.typeID()
		next = c.uint()
	case arrayKind, sliceKind:
		if next != 1 {
			return nil, errWire
		}
		t.elem = c.typeID()
		next = c.uint()
		if t.kind == arrayKind && next == 1 {
			v := c.uint()
			if v&1 != 0 || v>>1 > math.MaxInt32 {
				return nil, errWire
			}
			t.length = v >> 1
			next = c.uint()
		}
	default:
		return nil, errWire
	}
	if next != 0 || c.uint() != 0 || c.err != nil || len(c.data) != 0 {
		return nil, errWire
	}
	return t, nil
}

// Read reads exactly one self-contained gob stream emitted by an artifact
// writer. Bytes following the value belong to the caller (e.g. a signature).
func Read(r io.Reader, limit int64) ([]byte, error) {
	var out bytes.Buffer
	for frames := 0; ; frames++ {
		n, _, err := readUint(r, &out)
		if err != nil {
			return nil, err
		}
		left := limit - int64(out.Len())
		if left < 0 || n == 0 || n > uint64(left) {
			return nil, errors.New("gob frame exceeds artifact size limit")
		}
		id, width, err := readUint(io.LimitReader(r, int64(n)), &out)
		if err != nil {
			return nil, err
		}
		if id&1 != 0 && (frames >= maxTypes || n > maxDefinitionBytes) {
			return nil, errWire
		}
		if _, err := io.CopyN(&out, r, int64(n)-int64(width)); err != nil {
			return nil, err
		}
		if id&1 == 0 {
			return out.Bytes(), nil
		}
	}
}

func readUint(r io.Reader, out *bytes.Buffer) (uint64, int, error) {
	var buf [9]byte
	if _, err := io.ReadFull(r, buf[:1]); err != nil {
		return 0, 0, err
	}
	width := 1
	if buf[0] >= 128 {
		width += 256 - int(buf[0])
		if width > len(buf) {
			return 0, 0, errWire
		}
		if _, err := io.ReadFull(r, buf[1:width]); err != nil {
			return 0, 0, err
		}
	}
	out.Write(buf[:width])
	c := wireCursor{data: buf[:width]}
	return c.uint(), width, c.err
}
