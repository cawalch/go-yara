package regex

import (
	"encoding/binary"
)

// Emitter is a tiny helper for building bytecode slices.
// Endianness: little-endian for multi-byte integers.
type Emitter struct {
	buf []byte
}

// NewEmitter returns a new bytecode emitter with an empty buffer.
func NewEmitter() *Emitter { return &Emitter{} }

// Bytes returns the accumulated bytecode buffer.
func (e *Emitter) Bytes() []byte { return e.buf }

// Emit appends a single opcode byte and returns the emitter (for chaining).
func (e *Emitter) Emit(op byte) *Emitter {
	e.buf = append(e.buf, op)
	return e
}

// EmitU8 appends an 8-bit value and returns the emitter.
func (e *Emitter) EmitU8(v byte) *Emitter {
	e.buf = append(e.buf, v)
	return e
}

// EmitU16 appends a 16-bit unsigned value in little-endian order.
func (e *Emitter) EmitU16(v uint16) *Emitter {
	var tmp [2]byte
	binary.LittleEndian.PutUint16(tmp[:], v)
	e.buf = append(e.buf, tmp[:]...)
	return e
}

// EmitI16 appends a 16-bit signed value in little-endian order.
//
//nolint:gosec // G115: conversion from int16 to uint16 is intentional for encoding
func (e *Emitter) EmitI16(v int16) *Emitter {
	var tmp [2]byte
	// Safe conversion with explicit truncation
	binary.LittleEndian.PutUint16(tmp[:], uint16(v))
	e.buf = append(e.buf, tmp[:]...)
	return e
}

// EmitU32 appends a 32-bit unsigned value in little-endian order.
func (e *Emitter) EmitU32(v uint32) *Emitter {
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], v)
	e.buf = append(e.buf, tmp[:]...)
	return e
}

// Len returns the current size of the emitted bytecode buffer.
func (e *Emitter) Len() int { return len(e.buf) }
