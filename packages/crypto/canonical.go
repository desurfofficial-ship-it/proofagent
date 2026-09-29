package crypto

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
)

// CanonicalJSON produces deterministic JSON bytes per docs/CRYPTO.md:
// - UTF-8
// - sorted keys
// - compact (no whitespace)
// - no floats in signed objects (caller responsibility)
// - omit empty optional fields (caller responsibility via omitempty)
func CanonicalJSON(v any) ([]byte, error) {
	// First marshal to get a map/slice structure we can re-sort
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	var node any
	if err := json.Unmarshal(raw, &node); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	var buf bytes.Buffer
	if err := writeCanonical(&buf, node); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonical(buf *bytes.Buffer, node any) error {
	switch n := node.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if n {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case float64:
		// JSON numbers decode as float64. For integers that fit, write as int.
		if n == float64(int64(n)) {
			fmt.Fprintf(buf, "%d", int64(n))
		} else {
			// Forbidden in v0 signed objects, but still produce deterministic output
			fmt.Fprintf(buf, "%g", n)
		}
	case string:
		b, err := json.Marshal(n)
		if err != nil {
			return err
		}
		buf.Write(b)
	case []any:
		buf.WriteByte('[')
		for i, el := range n {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, el); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(n))
		for k := range n {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			kb, err := json.Marshal(k)
			if err != nil {
				return err
			}
			buf.Write(kb)
			buf.WriteByte(':')
			if err := writeCanonical(buf, n[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("unsupported type %T", node)
	}
	return nil
}
