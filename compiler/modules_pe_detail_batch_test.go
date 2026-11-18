package compiler

import (
	"fmt"
	"testing"

	"github.com/cawalch/go-yara/internal/pefixture"
)

func TestPEBatchedDetailViewsRemainDistinct(t *testing.T) {
	for _, is64 := range []bool{false, true} {
		data := pefixture.Exports(is64, 256)
		image := loadPE(&MatchContext{Data: data, FileSize: int64(len(data))})
		exports := image.exportField("export_details").object.elements
		clear(data) // Deferred fields must use the owned export snapshot.
		for index := len(exports) - 1; index >= 0; index-- {
			view := exports[index].object
			if got := view.field("name").String; got != fmt.Sprintf("Function%05d", index) {
				t.Fatalf("export %d: %q", index, got)
			}
			if view.field("ordinal").Integer != int64(index+7) || view.field("offset").Integer != 0x220 {
				t.Fatalf("export %d used another symbol's metadata", index)
			}
			if view.field("forward_name").Type != ModuleUndefined || view.field("unknown").Type != ModuleUndefined {
				t.Fatal("undefined export fields changed")
			}
		}

		data = pefixture.Imports(is64, 256)
		for index := range 256 {
			pefixture.ImportOrdinal(data, index, uint16(index))
		} //checkednarrow:ignore loop bounded to uint8 range
		image = loadPE(&MatchContext{Data: data, FileSize: int64(len(data))})
		library := image.importField("import_details").object.elements[0].object
		functions := library.field("functions").object.elements
		clear(data)
		for index := len(functions) - 1; index >= 0; index-- {
			view := functions[index].object
			want := fmt.Sprintf("ord%d", index)
			if got := view.field("name").String; got != want {
				t.Fatalf("import %d: %q want %q", index, got, want)
			}
			if view.field("ordinal").Integer != int64(index) || view.field("name").String != want {
				t.Fatalf("import %d cached another symbol's ordinal name", index)
			}
		}
	}
}
