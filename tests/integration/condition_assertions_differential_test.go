package integration

import (
	"fmt"
	"strconv"
	"testing"
)

func TestLibyaraConditionAssertions(t *testing.T) {
	conditions := []string{
		`uint16(0) == 0xffff`, `uint32(0) == 0xffffffff`,
		`0xffff == uint16(0)`, `uint16(0) == -1`,
		`int8(0) == -1 and uint8(0) == 255`,
		`int16(0) == -1 and uint16(0) == 65535`,
		`int32(0) == -1 and uint32(0) == 4294967295`,
		`uint16(0) == uint16be(0) and int16(0) == int16be(0)`,
		`$a at 4`, `$a at 6`, `$a at 0x7fffffffffffffff`, `$a at -1`,
		`filesize < 20MB and #a > 0 and $a at 4`,
		`not (filesize == 0) and #a > 1`,
	}
	for _, op := range []string{"==", "!=", "<", "<=", ">", ">="} {
		for _, target := range []string{"filesize", "#a"} {
			conditions = append(conditions, target+" "+op+" 2", "2 "+op+" "+target, target+" "+op+" -1", target+" "+op+" 0x7fffffffffffffff")
		}
	}
	for index, condition := range conditions {
		t.Run(strconv.Itoa(index), func(t *testing.T) {
			source := fmt.Sprintf(`rule probe { strings: $a = "MZ" condition: (%s) and $a }
rule inverse { strings: $a = "MZ" condition: not (%s) and $a }`, condition, condition)
			checkReleaseScanPaths(t, source, []byte("\xff\xff\xff\xffMZMZ"))
		})
	}
}
