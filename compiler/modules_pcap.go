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
	if cache != nil {
		cache.pcap = &result
	}
	return result
}

func scanPCAP(ctx *MatchContext) ModuleValue {
	if ctx.FileSize <= 0 || ctx.FileSize > pcap.MaxReaderAtScanBytes {
		return ModuleValue{}
	}
	records, err := captureTLSRecords(ctx)
	if err != nil {
		return ModuleValue{}
	}
	rows := make([]ModuleValue, len(records))
	for idx := range records {
		record := &records[idx]
		match, known := record.Handshake.ServerNameMatch()
		row := pcapTLSRow{flowIndex: record.FlowIndex, match: match, known: known}
		rows[idx] = ModuleValue{Type: ModuleStruct, object: &moduleObject{kind: ModuleStruct, getter: row}}
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

func (row pcapTLSRow) field(name string) ModuleValue {
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
