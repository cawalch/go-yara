package regex

import "testing"

func TestEmitterSequence(t *testing.T) {
	e := NewEmitter()
	e.Emit(OpLiteral).EmitU8('A').Emit(OpJump).EmitU16(0x1234).Emit(OpMatch)
	b := e.Bytes()
	want := []byte{OpLiteral, 'A', OpJump, 0x34, 0x12, OpMatch}
	if len(b) != len(want) {
		t.Fatalf("len=%d, want %d", len(b), len(want))
	}
	for i := range want {
		if b[i] != want[i] {
			t.Fatalf("byte[%d]=0x%x, want 0x%x", i, b[i], want[i])
		}
	}
}

