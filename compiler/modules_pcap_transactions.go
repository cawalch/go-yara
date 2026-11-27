package compiler

import (
	"strings"

	pcap "github.com/cawalch/go-pcap"
)

func pcapFields(integers, texts string) map[string]ModuleField {
	fields := make(map[string]ModuleField)
	for name := range strings.FieldsSeq(integers) {
		fields[name] = ModuleField{Kind: ModuleInteger}
	}
	for name := range strings.FieldsSeq(texts) {
		fields[name] = ModuleField{Kind: ModuleString}
	}
	return fields
}

func pcapStructField(fields map[string]ModuleField) ModuleField {
	return ModuleField{Kind: ModuleStruct, Struct: &ModuleSchema{Fields: fields}}
}

func pcapArrayField(element ModuleField) ModuleField {
	return ModuleField{Kind: ModuleArray, Element: &element}
}

var pcapHTTPField = func() ModuleField {
	fields := pcapFields("flow_index request_packet response_packet request_offset request_timestamp_ns response_timestamp_ns status source_port destination_port",
		"source destination method target authority pairing request_body response_body request_body_state response_body_state")
	header := pcapArrayField(pcapStructField(pcapFields("", "name value")))
	fields["request_headers"], fields["response_headers"] = header, header
	fields["packets"] = pcapArrayField(ModuleField{Kind: ModuleInteger})
	return pcapArrayField(pcapStructField(fields))
}()

var pcapDNSField = func() ModuleField {
	fields := pcapFields("flow_index packet_index timestamp_ns id rcode source_port destination_port question_count answer_count",
		"source destination")
	fields["complete"] = ModuleField{Kind: ModuleBoolean}
	fields["questions"] = pcapArrayField(pcapStructField(pcapFields("type class", "name")))
	fields["answers"] = pcapArrayField(pcapStructField(pcapFields("type class ttl", "name address target")))
	record := pcapStructField(fields)
	return pcapArrayField(pcapStructField(map[string]ModuleField{
		"query": record, "reply": record, "pairing": {Kind: ModuleString},
	}))
}()

func scanPCAPTransactions(ctx *MatchContext, state *pcapModuleCache, name string) ModuleValue {
	if ctx.FileSize <= 0 || scanCanceled(ctx.cancelDone) {
		return ModuleValue{}
	}
	if cache := ctx.moduleCache; name == "http" && cache != nil && cache.pcapHTTPRows != nil {
		return pcapRows(ctx, *cache.pcapHTTPRows, pcapHTTPValue)
	}
	capture, data, reader, err := pcapInput(ctx, state)
	if err != nil {
		return ModuleValue{}
	}
	if name == "http" {
		var rows []pcap.HTTP1Transaction
		if reader != nil {
			rows, err = capture.HTTP1TransactionsFromReaderAt(reader)
		} else {
			rows, err = capture.HTTP1Transactions(data)
		}
		if err != nil {
			return ModuleValue{}
		}
		return pcapRows(ctx, rows, pcapHTTPValue)
	}
	var rows []pcap.DNSTransaction
	if reader != nil {
		rows, err = capture.DNSTransactionsFromReaderAt(reader)
	} else {
		rows, err = capture.DNSTransactions(data)
	}
	if err != nil {
		return ModuleValue{}
	}
	return pcapRows(ctx, rows, pcapDNSValue)
}

func pcapRows[T any](ctx *MatchContext, input []T, value func(*T) ModuleValue) ModuleValue {
	if scanCanceled(ctx.cancelDone) {
		return ModuleValue{}
	}
	rows := make([]ModuleValue, len(input))
	for i := range input {
		if scanCanceledAt(ctx.cancelDone, i) {
			return ModuleValue{}
		}
		rows[i] = value(&input[i])
	}
	return peArray(rows)
}

func pcapHeaders(headers []pcap.HTTPHeader) ModuleValue {
	rows := make([]ModuleValue, len(headers))
	for i, h := range headers {
		rows[i] = peStruct(map[string]ModuleValue{"name": StringValue(h.Name), "value": StringValue(h.Value)})
	}
	return peArray(rows)
}

func pcapBody(data []byte, state pcap.HTTPBodyState) ModuleValue {
	if state == pcap.HTTPBodyComplete || state == pcap.HTTPBodyPartial {
		return StringValue(string(data))
	}
	return ModuleValue{}
}

func pcapBodyState(state pcap.HTTPBodyState) ModuleValue {
	switch state {
	case pcap.HTTPBodyComplete:
		return StringValue("complete")
	case pcap.HTTPBodyPartial:
		return StringValue("partial")
	case pcap.HTTPBodyUnsupported:
		return StringValue("unsupported")
	default:
		return StringValue("unknown")
	}
}

func pcapTime(ns int64) ModuleValue {
	if ns == 0 {
		return ModuleValue{}
	}
	return IntegerValue(ns)
}

func pcapHTTPValue(tx *pcap.HTTP1Transaction) ModuleValue {
	// Convert binary bodies at most once per scan, on first evaluated access.
	var body [2]*ModuleValue
	return peLazyStruct(func(name string) ModuleValue {
		req, rsp := &tx.Request, tx.Response
		switch name {
		case "flow_index":
			return IntegerValue(int64(req.FlowIndex))
		case "request_packet":
			return IntegerValue(int64(req.PacketIndex))
		case "request_offset":
			return IntegerValue(int64(req.PacketPayloadOffset))
		case "request_timestamp_ns":
			return pcapTime(req.TimestampNs)
		case "source":
			return StringValue(req.Source.Addr().String())
		case "destination":
			return StringValue(req.Destination.Addr().String())
		case "source_port":
			return IntegerValue(int64(req.Source.Port()))
		case "destination_port":
			return IntegerValue(int64(req.Destination.Port()))
		case "method":
			return StringValue(req.Method)
		case "target":
			return StringValue(req.Target)
		case "authority":
			if req.Authority != "" {
				return StringValue(req.Authority)
			}
		case "pairing":
			switch tx.Pairing {
			case pcap.HTTP1ResponseConfirmed:
				return StringValue("confirmed")
			case pcap.HTTP1ResponseAmbiguous:
				return StringValue("ambiguous")
			default:
				return StringValue("unseen")
			}
		case "request_headers":
			return pcapHeaders(req.Headers)
		case "request_body":
			if body[0] == nil {
				value := pcapBody(req.Body, req.BodyState)
				body[0] = &value
			}
			return *body[0]
		case "request_body_state":
			return pcapBodyState(req.BodyState)
		case "packets":
			packets := make([]ModuleValue, len(tx.PacketIndices))
			for i, index := range tx.PacketIndices {
				packets[i] = IntegerValue(int64(index))
			}
			return peArray(packets)
		}
		if rsp == nil {
			return ModuleValue{}
		}
		switch name {
		case "response_packet":
			return IntegerValue(int64(rsp.PacketIndex))
		case "response_timestamp_ns":
			return pcapTime(rsp.TimestampNs)
		case "status":
			return IntegerValue(int64(rsp.StatusCode))
		case "response_headers":
			return pcapHeaders(rsp.Headers)
		case "response_body":
			if body[1] == nil {
				value := pcapBody(rsp.Body, rsp.BodyState)
				body[1] = &value
			}
			return *body[1]
		case "response_body_state":
			return pcapBodyState(rsp.BodyState)
		}
		return ModuleValue{}
	})
}

func pcapDNSValue(tx *pcap.DNSTransaction) ModuleValue {
	pairing := "unsupported"
	switch tx.Pairing {
	case pcap.DNSPaired:
		pairing = "paired"
	case pcap.DNSNoReplyObserved:
		pairing = "no_reply_observed"
	case pcap.DNSNoQueryObserved:
		pairing = "no_query_observed"
	case pcap.DNSAmbiguous:
		pairing = "ambiguous"
	}
	return peStruct(map[string]ModuleValue{
		"pairing": StringValue(pairing), "query": pcapDNSRecord(tx.Query), "reply": pcapDNSRecord(tx.Reply),
	})
}

func pcapDNSRecord(record *pcap.DNSRecord) ModuleValue {
	if record == nil {
		return ModuleValue{}
	}
	m := &record.Message
	return peLazyStruct(func(name string) ModuleValue {
		switch name {
		case "flow_index":
			return IntegerValue(int64(record.FlowIndex))
		case "packet_index":
			return IntegerValue(int64(record.PacketIndex))
		case "timestamp_ns":
			return pcapTime(record.TimestampNs)
		case "source":
			return StringValue(record.SrcAddr.String())
		case "destination":
			return StringValue(record.DstAddr.String())
		case "source_port":
			return IntegerValue(int64(record.SrcPort))
		case "destination_port":
			return IntegerValue(int64(record.DstPort))
		case "id":
			return IntegerValue(int64(m.TransactionID))
		case "rcode":
			code := int64(m.RCode)
			for _, rr := range m.Additionals {
				if rr.Type == pcap.DNSTypeOPT {
					code |= int64(rr.TTL>>24) << 4
					break
				}
			}
			return IntegerValue(code)
		case "complete":
			return BooleanValue(!m.Truncated && !m.Anomalies.Any())
		case "question_count":
			return IntegerValue(int64(m.QuestionCount))
		case "answer_count":
			return IntegerValue(int64(m.AnswerCount))
		case "questions":
			rows := make([]ModuleValue, len(m.Questions))
			for i, q := range m.Questions {
				rows[i] = peStruct(map[string]ModuleValue{
					"name": StringValue(q.Name), "type": IntegerValue(int64(q.Type)), "class": IntegerValue(int64(q.Class)),
				})
			}
			return peArray(rows)
		case "answers":
			rows := make([]ModuleValue, len(m.Answers))
			for i, answer := range m.Answers {
				fields := map[string]ModuleValue{
					"name": StringValue(answer.Name), "type": IntegerValue(int64(answer.Type)),
					"class": IntegerValue(int64(answer.Class)), "ttl": IntegerValue(int64(answer.TTL)),
				}
				if answer.Address.IsValid() {
					fields["address"] = StringValue(answer.Address.String())
				}
				if answer.Type == pcap.DNSTypeCNAME && answer.Target != "" {
					fields["target"] = StringValue(answer.Target)
				}
				rows[i] = peStruct(fields)
			}
			return peArray(rows)
		}
		return ModuleValue{}
	})
}
