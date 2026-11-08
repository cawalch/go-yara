package compiler

import (
	"encoding/base64"
	"io"
	"slices"
	"strconv"
)

// AppendEvidenceJSON appends the JSON representation of evidence findings to dst
// without reflection or intermediate map materialization.
func AppendEvidenceJSON(dst []byte, evidence map[string][]EvidenceFinding) []byte {
	if len(evidence) == 0 {
		return append(dst, '{', '}')
	}

	// Sort plan names deterministically.
	var plansBuf [8]string
	plans := plansBuf[:0]
	for plan := range evidence {
		plans = append(plans, plan)
	}
	if len(plans) > 1 {
		slices.Sort(plans)
	}

	dst = append(dst, '{')
	for i, plan := range plans {
		if i > 0 {
			dst = append(dst, ',')
		}
		dst = appendJSONString(dst, plan)
		dst = append(dst, ':', '[')
		findings := evidence[plan]
		for j := range findings {
			if j > 0 {
				dst = append(dst, ',')
			}
			dst = findings[j].AppendJSON(dst)
		}
		dst = append(dst, ']')
	}
	dst = append(dst, '}')
	return dst
}

// WriteEvidenceJSON writes the JSON representation of evidence findings directly
// to w without reflection or intermediate allocations.
func WriteEvidenceJSON(w io.Writer, evidence map[string][]EvidenceFinding) error {
	buf := AppendEvidenceJSON(nil, evidence)
	_, err := w.Write(buf)
	return err
}

// AppendJSON appends the JSON representation of an EvidenceFinding to dst.
func (f *EvidenceFinding) AppendJSON(dst []byte) []byte {
	dst = append(dst, `{"Anchor":`...)
	dst = f.Anchor.AppendJSON(dst)
	dst = append(dst, `,"Status":`...)
	dst = appendJSONString(dst, string(f.Status))
	dst = append(dst, `,"Fields":{`...)

	if len(f.Fields) > 0 {
		var fieldsBuf [8]string
		fields := fieldsBuf[:0]
		for field := range f.Fields {
			fields = append(fields, field)
		}
		if len(fields) > 1 {
			slices.Sort(fields)
		}
		for i, field := range fields {
			if i > 0 {
				dst = append(dst, ',')
			}
			dst = appendJSONString(dst, field)
			dst = append(dst, ':', '[')
			captures := f.Fields[field]
			for j := range captures {
				if j > 0 {
					dst = append(dst, ',')
				}
				dst = captures[j].AppendJSON(dst)
			}
			dst = append(dst, ']')
		}
	}
	dst = append(dst, '}', '}')
	return dst
}

// WriteJSON writes the JSON representation of an EvidenceFinding to w.
func (f *EvidenceFinding) WriteJSON(w io.Writer) error {
	buf := f.AppendJSON(nil)
	_, err := w.Write(buf)
	return err
}

// AppendJSON appends the JSON representation of a Capture to dst.
func (c *Capture) AppendJSON(dst []byte) []byte {
	dst = append(dst, `{"Name":`...)
	dst = appendJSONString(dst, c.Name)
	dst = append(dst, `,"Pattern":`...)
	dst = appendJSONString(dst, c.Pattern)
	dst = append(dst, `,"Group":`...)
	dst = strconv.AppendInt(dst, int64(c.Group), 10)
	dst = append(dst, `,"Offset":`...)
	dst = strconv.AppendInt(dst, c.Offset, 10)
	dst = append(dst, `,"Length":`...)
	dst = strconv.AppendInt(dst, int64(c.Length), 10)
	dst = append(dst, `,"Data":`...)
	switch {
	case c.Data == nil:
		dst = append(dst, "null"...)
	case len(c.Data) == 0:
		dst = append(dst, `""`...)
	default:
		dst = append(dst, '"')
		encodedLen := base64.StdEncoding.EncodedLen(len(c.Data))
		start := len(dst)
		dst = slices.Grow(dst, encodedLen)
		dst = dst[:start+encodedLen]
		base64.StdEncoding.Encode(dst[start:], c.Data)
		dst = append(dst, '"')
	}
	dst = append(dst, `,"DataTruncated":`...)
	dst = strconv.AppendBool(dst, c.DataTruncated)
	dst = append(dst, '}')
	return dst
}

// WriteJSON writes the JSON representation of a Capture to w.
func (c *Capture) WriteJSON(w io.Writer) error {
	buf := c.AppendJSON(nil)
	_, err := w.Write(buf)
	return err
}

func appendJSONString(dst []byte, s string) []byte {
	dst = append(dst, '"')
	for i := 0; i < len(s); i++ {
		b := s[i]
		switch b {
		case '"':
			dst = append(dst, '\\', '"')
		case '\\':
			dst = append(dst, '\\', '\\')
		case '\n':
			dst = append(dst, '\\', 'n')
		case '\r':
			dst = append(dst, '\\', 'r')
		case '\t':
			dst = append(dst, '\\', 't')
		default:
			if b < 0x20 {
				const hex = "0123456789abcdef"
				dst = append(dst, '\\', 'u', '0', '0', hex[b>>4], hex[b&0xf])
			} else {
				dst = append(dst, b)
			}
		}
	}
	dst = append(dst, '"')
	return dst
}
