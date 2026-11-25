package goblimit

import (
	"bytes"
	"encoding/gob"
	"errors"
	"io"
	"reflect"
	"testing"
)

func TestBudgetAccountsForCollections(t *testing.T) {
	type record struct {
		Name    string
		Fixed   [3]uint16
		Bitsets [][]byte
	}
	type catalog struct {
		Records map[string]*record
		List    []record
	}
	entry := record{"abc", [3]uint16{1, 2, 3}, [][]byte{{1}, {2}, {3}}}
	value := catalog{map[string]*record{"r": &entry}, []record{entry}}
	var data bytes.Buffer
	if err := gob.NewEncoder(&data).Encode(value); err != nil {
		t.Fatal(err)
	}
	blob := data.Bytes()
	for _, limit := range []int{32, 1024} {
		used, err := Check(blob, reflect.TypeFor[catalog](), limit)
		if limit == 32 {
			if !errors.Is(err, errBudget) {
				t.Fatalf("small decoded budget: %v", err)
			}
		} else if err != nil || used != len(blob) {
			t.Fatalf("used=%d of %d bytes: %v", used, len(blob), err)
		}
	}
	stream := io.MultiReader(bytes.NewReader(blob), bytes.NewReader([]byte("tail")))
	got, err := Read(stream, int64(len(blob)))
	if err != nil || !bytes.Equal(got, blob) {
		t.Fatalf("read: %v", err)
	}
	tail, err := io.ReadAll(stream)
	if err != nil || string(tail) != "tail" {
		t.Fatalf("tail %q: %v", tail, err)
	}
}

func TestDeclaredFieldLimit(t *testing.T) {
	type sample struct {
		Other   [][]byte
		Bounded [][]byte `gobmax:"2"`
	}
	for _, count := range []int{2, 3} {
		var data bytes.Buffer
		if err := gob.NewEncoder(&data).Encode(sample{Other: make([][]byte, 5), Bounded: make([][]byte, count)}); err != nil {
			t.Fatal(err)
		}
		_, err := Check(data.Bytes(), reflect.TypeFor[sample](), 1024)
		if count == 2 && err != nil || count == 3 && !errors.Is(err, errBudget) {
			t.Fatalf("count %d: %v", count, err)
		}
	}
}
