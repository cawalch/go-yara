package compiler

import pcap "github.com/cawalch/go-pcap"

var pcapSchema = &ModuleSchema{Fields: map[string]ModuleField{
	"tls": {Kind: ModuleArray, Element: &ModuleField{Kind: ModuleStruct, Struct: &ModuleSchema{Fields: map[string]ModuleField{
		"flow_index":        {Kind: ModuleInteger},
		"server_name_match": {Kind: ModuleBoolean},
	}}}},
}}

// Keep a module-presence probe independent of capture parsing. Only a
// request for the tls field needs to inspect the input.
type pcapModuleRoot struct{ ctx *MatchContext }

func loadPCAP(ctx *MatchContext) ModuleValue {
	return ModuleValue{Type: ModuleStruct, object: &moduleObject{kind: ModuleStruct, getter: pcapModuleRoot{ctx}}}
}

func (root pcapModuleRoot) field(name string) ModuleValue {
	ctx := root.ctx
	if ctx == nil || name != "tls" {
		return ModuleValue{}
	}
	cache := ctx.moduleCache
	if cache != nil && cache.pcap != nil {
		return *cache.pcap
	}
	result := scanPCAP(ctx)
	if cache != nil && !scanCanceled(ctx.cancelDone) {
		cache.pcap = &result
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

func captureTLSRecords(ctx *MatchContext) ([]pcap.TLSRecord, error) {
	if cache := ctx.moduleCache; cache != nil && cache.pcapReader != nil {
		capture, err := pcap.NewFromReaderAt(cache.pcapReader, ctx.FileSize)
		if err != nil {
			return nil, err
		}
		return capture.TLSFromReaderAt(cache.pcapReader)
	}
	if ctx.FileSize > pcap.MaxReaderAtScanBytes {
		return nil, pcap.ErrPacketLimit
	}
	data, ok := peFullScanData(ctx)
	if !ok {
		return nil, pcap.ErrInvalidHeader
	}
	capture, err := pcap.New(data)
	if err != nil {
		return nil, err
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
