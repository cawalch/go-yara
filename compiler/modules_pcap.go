package compiler

import (
	"io"
	"reflect"

	pcap "github.com/cawalch/go-pcap"
)

var pcapTLSSchema = &ModuleSchema{Fields: map[string]ModuleField{
	"tls": {Kind: ModuleArray, Element: &ModuleField{Kind: ModuleStruct, Struct: &ModuleSchema{Fields: map[string]ModuleField{
		"flow_index":        {Kind: ModuleInteger},
		"server_name_match": {Kind: ModuleBoolean},
	}}}},
}}

var pcapSchema = &ModuleSchema{Fields: map[string]ModuleField{
	"tls":               pcapTLSSchema.Fields["tls"],
	"http":              pcapHTTPField,
	"dns":               pcapDNSField,
	"capture_truncated": {Kind: ModuleBoolean},
}}

func nativePCAPSchema(schema *ModuleSchema) bool {
	return schema == pcapSchema || (schema != nil &&
		(reflect.DeepEqual(schema, pcapSchema) || reflect.DeepEqual(schema, pcapTLSSchema)))
}

// Importing the module does not parse the capture.
type pcapModuleRoot struct{ ctx *MatchContext }

func loadPCAP(ctx *MatchContext) ModuleValue {
	return ModuleValue{Type: ModuleStruct, object: &moduleObject{kind: ModuleStruct, getter: pcapModuleRoot{ctx}}}
}

type pcapModuleCache struct {
	capture *pcap.Capture
	results [4]*ModuleValue
}

func (root pcapModuleRoot) field(name string) ModuleValue {
	ctx := root.ctx
	if ctx == nil || scanCanceled(ctx.cancelDone) {
		return ModuleValue{}
	}
	var index int
	switch name {
	case "tls":
		index = 0
	case "http":
		index = 1
	case "dns":
		index = 2
	case "capture_truncated":
		index = 3
	default:
		return ModuleValue{}
	}
	cache := ctx.moduleCache
	var state *pcapModuleCache
	if cache != nil {
		state = cache.pcap
	}
	if state == nil {
		state = new(pcapModuleCache)
	} else if value := state.results[index]; value != nil {
		return *value
	}
	var result ModuleValue
	switch name {
	case "capture_truncated":
		capture, _, _, err := pcapInput(ctx, state)
		if err == nil {
			result = BooleanValue(capture.InputTruncated())
		}
	case "tls":
		result = scanPCAP(ctx, state)
	case "http", "dns":
		result = scanPCAPTransactions(ctx, state, name)
	}
	if scanCanceled(ctx.cancelDone) {
		return ModuleValue{}
	}
	if cache != nil {
		state.results[index] = &result
		cache.pcap = state
	}
	return result
}

func scanPCAP(ctx *MatchContext, state *pcapModuleCache) ModuleValue {
	if scanCanceled(ctx.cancelDone) {
		return ModuleValue{}
	}
	if ctx.FileSize <= 0 {
		return ModuleValue{}
	}
	records, err := captureTLSRecords(ctx, state)
	if err != nil || scanCanceled(ctx.cancelDone) {
		return ModuleValue{}
	}
	rows := make([]ModuleValue, len(records))
	rowData := make([]pcapTLSRow, len(records))
	objs := make([]moduleObject, len(records))
	for idx := range records {
		if scanCanceledAt(ctx.cancelDone, idx) {
			return ModuleValue{}
		}
		record := &records[idx]
		match, known := record.Handshake.ServerNameMatch()
		rowData[idx] = pcapTLSRow{flowIndex: record.FlowIndex, match: match, known: known}
		objs[idx] = moduleObject{kind: ModuleStruct, getter: &rowData[idx]}
		rows[idx] = ModuleValue{Type: ModuleStruct, object: &objs[idx]}
	}
	if scanCanceled(ctx.cancelDone) {
		return ModuleValue{}
	}
	return ModuleValue{Type: ModuleArray, object: &moduleObject{kind: ModuleArray, elements: rows}}
}

func pcapInput(ctx *MatchContext, state *pcapModuleCache) (*pcap.Capture, []byte, io.ReaderAt, error) {
	cache := ctx.moduleCache
	var data []byte
	var reader io.ReaderAt
	if cache != nil {
		reader = cache.pcapReader
	}
	if reader == nil {
		if ctx.FileSize > pcap.MaxReaderAtScanBytes {
			return nil, nil, nil, pcap.ErrPacketLimit
		}
		var ok bool
		data, ok = peFullScanData(ctx)
		if !ok {
			return nil, nil, nil, pcap.ErrInvalidHeader
		}
	}
	if state.capture != nil {
		return state.capture, data, reader, nil
	}
	var capture *pcap.Capture
	var err error
	if reader != nil {
		capture, err = pcap.NewFromReaderAt(reader, ctx.FileSize)
	} else {
		capture, err = pcap.New(data)
	}
	if err == nil && !scanCanceled(ctx.cancelDone) {
		state.capture = capture
	}
	return capture, data, reader, err
}

func captureTLSRecords(ctx *MatchContext, state *pcapModuleCache) ([]pcap.TLSRecord, error) {
	capture, data, reader, err := pcapInput(ctx, state)
	if err != nil {
		return nil, err
	}
	if reader != nil {
		return capture.TLSFromReaderAt(reader)
	}
	return capture.TLS(data)
}

type pcapTLSRow struct {
	flowIndex    int
	match, known bool
}

func (row *pcapTLSRow) field(name string) ModuleValue {
	if row == nil {
		return ModuleValue{}
	}
	switch name {
	case "flow_index":
		return IntegerValue(int64(row.flowIndex))
	case "server_name_match":
		if row.known {
			return BooleanValue(row.match)
		}
	}
	return ModuleValue{}
}
