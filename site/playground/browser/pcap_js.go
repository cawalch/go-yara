//go:build js && wasm && pcap_preview

package main

import (
	"context"
	"encoding/json"
	"io"
	"syscall/js"
	"time"

	pcap "github.com/cawalch/go-pcap"

	"github.com/cawalch/go-yara/internal/rulecompare"
	"github.com/cawalch/go-yara/site/playground/engine"
)

func init() {
	js.Global().Set("goYaraCompare", js.FuncOf(comparePCAP))
	js.Global().Set("goYaraProbe", js.FuncOf(probePCAP))
}

func comparePCAP(_ js.Value, args []js.Value) any {
	if len(args) != 5 {
		return errorReply("Invalid comparison request.")
	}
	baseline, candidate := args[0].String(), args[1].String()
	size := args[4].Get("byteLength").Int()
	if len(baseline) > engine.Limits.RulesBytes || len(candidate) > engine.Limits.RulesBytes || size > engine.Limits.InputBytes {
		return errorReply("Rule source or capture exceeds the playground limit.")
	}
	data := make([]byte, size)
	js.CopyBytesToGo(data, args[4])
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(engine.Limits.TimeoutMs)*time.Millisecond)
	defer cancel()
	report, err := rulecompare.ReviewCapture(ctx, rulecompare.CaptureReview{
		Baseline: baseline, Candidate: candidate, Rule: args[2].String(), Fixture: args[3].String(),
		Data: data, InputLimit: engine.Limits.InputBytes,
	})
	if ctx.Err() != nil {
		return errorReply("Comparison timed out. No complete result is available.")
	}
	if err != nil {
		return errorReply(err.Error())
	}
	return string(report)
}

type blobReader struct {
	blob, reader, uint8Array js.Value
	size                     int64
	bytesRead, reads         int
}

func (r *blobReader) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= r.size {
		return 0, io.EOF
	}
	end := min(off+int64(len(p)), r.size)
	//checkednarrow:ignore the worker bounds Blob size before constructing the reader.
	part := r.blob.Call("slice", int(off), int(end))
	data := r.reader.Call("readAsArrayBuffer", part)
	n := js.CopyBytesToGo(p, r.uint8Array.New(data))
	r.bytesRead += n
	r.reads++
	if n != len(p) {
		return n, io.EOF
	}
	return n, nil
}

type probeArtifact struct {
	RequestPacket  int `json:"request_packet"`
	ResponsePacket int `json:"response_packet"`
	DecodedBytes   int `json:"decoded_bytes"`
}

func probePCAP(_ js.Value, args []js.Value) any {
	if len(args) != 2 {
		return errorReply("Invalid reader probe request.")
	}
	size := args[0].Get("size").Int()
	if size > engine.Limits.InputBytes {
		return errorReply("Capture exceeds the playground limit.")
	}
	reader := &blobReader{
		blob: args[0], reader: js.Global().Get("FileReaderSync").New(),
		uint8Array: js.Global().Get("Uint8Array"), size: int64(size),
	}
	start := time.Now()
	rows, err := probeRows(reader, args[1].Bool())
	if err != nil {
		return errorReply("Reader probe could not decode the capture.")
	}
	result := struct {
		Reads     int             `json:"reads"`
		BytesRead int             `json:"bytes_read"`
		ElapsedMs float64         `json:"elapsed_ms"`
		Artifacts []probeArtifact `json:"artifacts"`
	}{
		Reads: reader.reads, BytesRead: reader.bytesRead,
		ElapsedMs: float64(time.Since(start).Nanoseconds()) / 1e6, Artifacts: []probeArtifact{},
	}
	for _, row := range rows {
		artifact := row.ResponseArtifact()
		if artifact.Coverage == pcap.HTTP1ArtifactComplete {
			result.Artifacts = append(result.Artifacts, probeArtifact{
				RequestPacket: artifact.ID.PacketIndex, ResponsePacket: artifact.ResponsePacketIndex, DecodedBytes: len(artifact.Body),
			})
		}
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return errorReply("Could not encode reader results.")
	}
	return string(encoded)
}

func probeRows(reader *blobReader, seekable bool) ([]pcap.HTTP1Transaction, error) {
	if seekable {
		capture, err := pcap.NewFromReaderAt(reader, reader.size)
		if err != nil {
			return nil, err
		}
		return capture.HTTP1TransactionsFromReaderAt(reader)
	}
	data := make([]byte, reader.size)
	if _, err := reader.ReadAt(data, 0); err != nil {
		return nil, err
	}
	capture, err := pcap.New(data)
	if err != nil {
		return nil, err
	}
	return capture.HTTP1Transactions(data)
}

func errorReply(message string) string {
	encoded, _ := json.Marshal(struct {
		Error string `json:"error"`
	}{message})
	return string(encoded)
}
