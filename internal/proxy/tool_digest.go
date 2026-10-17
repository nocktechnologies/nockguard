package proxy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/big"
	"slices"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

const toolHashVersion = "jcs-rfc8785-v1"
const toolHashDomain = "nockguard:mcp-tool:jcs-rfc8785-v1\x00"

// digestToolDefinition hashes exactly one complete MCP Tool object. The parser
// rejects duplicate members before encoding/json can collapse them.
func digestToolDefinition(raw json.RawMessage) (string, string, error) {
	if err := validateJSONStringLiterals(raw); err != nil {
		return "", "", err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	v, err := readJCSValue(dec, 0)
	if err != nil {
		return "", "", err
	}
	if _, err := dec.Token(); err != io.EOF {
		return "", "", fmt.Errorf("trailing tool definition data")
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return "", "", fmt.Errorf("tool definition is not an object")
	}
	for key := range obj {
		for _, field := range []string{"name", "description", "inputSchema", "outputSchema", "annotations", "title", "_meta"} {
			if key != field && strings.EqualFold(key, field) {
				return "", "", fmt.Errorf("tool structural field alias")
			}
		}
	}
	name, ok := obj["name"].(string)
	if !ok || name == "" {
		return "", "", fmt.Errorf("tool name is missing")
	}
	if _, ok := obj["inputSchema"].(map[string]any); !ok {
		return "", "", fmt.Errorf("tool inputSchema is missing or invalid")
	}
	for _, field := range []string{"description", "title"} {
		if value, exists := obj[field]; exists {
			if _, ok := value.(string); !ok {
				return "", "", fmt.Errorf("invalid tool %s", field)
			}
		}
	}
	for _, field := range []string{"outputSchema", "annotations", "_meta"} {
		if value, exists := obj[field]; exists {
			if _, ok := value.(map[string]any); !ok {
				return "", "", fmt.Errorf("invalid tool %s", field)
			}
		}
	}
	var canonical bytes.Buffer
	if err := writeJCS(&canonical, v); err != nil {
		return "", "", err
	}
	sum := sha256.Sum256(append([]byte(toolHashDomain), canonical.Bytes()...))
	return name, hex.EncodeToString(sum[:]), nil
}

func readJCSValue(dec *json.Decoder, depth int) (any, error) {
	if depth > 128 {
		return nil, fmt.Errorf("tool definition nesting limit")
	}
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if delim, ok := tok.(json.Delim); ok {
		switch delim {
		case '{':
			obj := make(map[string]any)
			for dec.More() {
				keyToken, err := dec.Token()
				if err != nil {
					return nil, err
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, fmt.Errorf("invalid object key")
				}
				if _, exists := obj[key]; exists {
					return nil, fmt.Errorf("duplicate tool definition member")
				}
				value, err := readJCSValue(dec, depth+1)
				if err != nil {
					return nil, err
				}
				obj[key] = value
			}
			_, err := dec.Token()
			return obj, err
		case '[':
			var values []any
			for dec.More() {
				value, err := readJCSValue(dec, depth+1)
				if err != nil {
					return nil, err
				}
				values = append(values, value)
			}
			_, err := dec.Token()
			return values, err
		}
		return nil, fmt.Errorf("unexpected JSON delimiter")
	}
	return tok, nil
}

// Go's JSON decoder replaces malformed surrogate escapes. Reject them before
// decoding so two distinct inputs cannot silently acquire the same digest.
func validateJSONStringLiterals(raw []byte) error {
	if !utf8.Valid(raw) {
		return fmt.Errorf("invalid UTF-8 in tool definition")
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] != '"' {
			continue
		}
		i++
		for i < len(raw) {
			if raw[i] == '\\' {
				if i+1 >= len(raw) {
					return fmt.Errorf("incomplete JSON escape")
				}
				switch raw[i+1] {
				case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
					i += 2
				case 'u':
					if i+6 > len(raw) {
						return fmt.Errorf("incomplete Unicode escape")
					}
					unit, err := strconv.ParseUint(string(raw[i+2:i+6]), 16, 16)
					if err != nil {
						return fmt.Errorf("invalid Unicode escape")
					}
					if unit >= 0xd800 && unit <= 0xdbff {
						if i+12 > len(raw) || raw[i+6] != '\\' || raw[i+7] != 'u' {
							return fmt.Errorf("unpaired Unicode surrogate")
						}
						low, err := strconv.ParseUint(string(raw[i+8:i+12]), 16, 16)
						if err != nil || low < 0xdc00 || low > 0xdfff {
							return fmt.Errorf("unpaired Unicode surrogate")
						}
						i += 12
					} else if unit >= 0xdc00 && unit <= 0xdfff {
						return fmt.Errorf("unpaired Unicode surrogate")
					} else {
						i += 6
					}
				default:
					return fmt.Errorf("invalid JSON escape")
				}
				continue
			}
			if raw[i] == '"' {
				break
			}
			if raw[i] < 0x20 {
				return fmt.Errorf("unescaped JSON control character")
			}
			i++
		}
		if i >= len(raw) {
			return fmt.Errorf("unterminated JSON string")
		}
	}
	return nil
}

func writeJCS(out *bytes.Buffer, value any) error {
	switch v := value.(type) {
	case nil:
		out.WriteString("null")
	case bool:
		if v {
			out.WriteString("true")
		} else {
			out.WriteString("false")
		}
	case string:
		out.WriteByte('"')
		for _, r := range v {
			switch r {
			case '"':
				out.WriteString(`\"`)
			case '\\':
				out.WriteString(`\\`)
			case '\b':
				out.WriteString(`\b`)
			case '\f':
				out.WriteString(`\f`)
			case '\n':
				out.WriteString(`\n`)
			case '\r':
				out.WriteString(`\r`)
			case '\t':
				out.WriteString(`\t`)
			default:
				if r < 0x20 {
					fmt.Fprintf(out, "\\u%04x", r)
				} else {
					out.WriteRune(r)
				}
			}
		}
		out.WriteByte('"')
	case json.Number:
		n, err := canonicalJCSNumber(string(v))
		if err != nil {
			return err
		}
		out.WriteString(n)
	case []any:
		out.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := writeJCS(out, item); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		slices.SortFunc(keys, func(a, b string) int { return slices.Compare(utf16.Encode([]rune(a)), utf16.Encode([]rune(b))) })
		out.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := writeJCS(out, key); err != nil {
				return err
			}
			out.WriteByte(':')
			if err := writeJCS(out, v[key]); err != nil {
				return err
			}
		}
		out.WriteByte('}')
	default:
		return fmt.Errorf("unsupported tool definition value")
	}
	return nil
}

func canonicalJCSNumber(raw string) (string, error) {
	f, err := strconv.ParseFloat(raw, 64)
	if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
		return "", fmt.Errorf("tool number outside IEEE-754 range")
	}
	if f == 0 {
		if !decimalIsZero(raw) {
			return "", fmt.Errorf("tool number underflows IEEE-754")
		}
		return "0", nil
	}
	var canonical string
	if math.Abs(f) >= 1e-6 && math.Abs(f) < 1e21 {
		canonical = strconv.FormatFloat(f, 'f', -1, 64)
	} else {
		canonical = strconv.FormatFloat(f, 'e', -1, 64)
		if i := strings.IndexByte(canonical, 'e'); i >= 0 {
			exp, _ := strconv.Atoi(canonical[i+1:])
			canonical = canonical[:i] + "e" + fmt.Sprintf("%+d", exp)
		}
	}
	a, okA := decimalRat(raw)
	b, okB := decimalRat(canonical)
	if !okA || !okB || a.Cmp(b) != 0 {
		return "", fmt.Errorf("tool number loses precision in IEEE-754")
	}
	return canonical, nil
}

func decimalIsZero(s string) bool {
	for _, c := range s {
		if c >= '1' && c <= '9' {
			return false
		}
	}
	return true
}

func decimalRat(s string) (*big.Rat, bool) {
	mantissa, exponent, hasExponent := strings.Cut(strings.ToLower(s), "e")
	exp := 0
	if hasExponent {
		var err error
		exp, err = strconv.Atoi(exponent)
		if err != nil || exp < -400 || exp > 400 {
			return nil, false
		}
	}
	if point := strings.IndexByte(mantissa, '.'); point >= 0 {
		exp -= len(mantissa) - point - 1
		mantissa = strings.ReplaceAll(mantissa, ".", "")
	}
	if exp < -400 || exp > 400 {
		return nil, false
	}
	n := new(big.Int)
	if _, ok := n.SetString(mantissa, 10); !ok {
		return nil, false
	}
	r := new(big.Rat).SetInt(n)
	pow := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(max(exp, -exp))), nil)
	if exp < 0 {
		r.Quo(r, new(big.Rat).SetInt(pow))
	} else {
		r.Mul(r, new(big.Rat).SetInt(pow))
	}
	return r, true
}
