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

func (root pcapModuleRoot) field(name string) ModuleValue {
	ctx := root.ctx
	if ctx == nil || scanCanceled(ctx.cancelDone) {
		return ModuleValue{}
	}
	cache := ctx.moduleCache
	var result ModuleValue
	switch name {
	case "capture_truncated":
		capture, _, _, err := pcapInput(ctx)
		if err == nil && !scanCanceled(ctx.cancelDone) {
			return BooleanValue(capture.InputTruncated())
		}
	case "tls":
		if cache != nil && cache.pcap != nil {
			return *cache.pcap
		}
		result = scanPCAP(ctx)
		if cache != nil && !scanCanceled(ctx.cancelDone) {
			cache.pcap = &result
		}
	case "http", "dns":
		if cache != nil {
			if value, ok := cache.pcapTransactions[name]; ok {
				return value
			}
		}
		result = scanPCAPTransactions(ctx, name)
		if cache != nil && !scanCanceled(ctx.cancelDone) {
			if cache.pcapTransactions == nil {
				cache.pcapTransactions = make(map[string]ModuleValue, 2)
			}
			cache.pcapTransactions[name] = result
		}
	}
	return result
}

func scanPCAP(ctx *MatchContext) ModuleValue {
	if scanCanceled(ctx.cancelDone) {
		return ModuleValue{}
	}
	if ctx.FileSize <= 0 {
		return ModuleValue{}
	}
	records, err := captureTLSRecords(ctx)
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

func pcapInput(ctx *MatchContext) (*pcap.Capture, []byte, io.ReaderAt, error) {
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
	if cache != nil && cache.pcapCapture != nil {
		return cache.pcapCapture, data, reader, nil
	}
	var capture *pcap.Capture
	var err error
	if reader != nil {
		capture, err = pcap.NewFromReaderAt(reader, ctx.FileSize)
	} else {
		capture, err = pcap.New(data)
	}
	if err == nil && cache != nil && !scanCanceled(ctx.cancelDone) {
		cache.pcapCapture = capture
	}
	return capture, data, reader, err
}

func captureTLSRecords(ctx *MatchContext) ([]pcap.TLSRecord, error) {
	capture, data, reader, err := pcapInput(ctx)
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
