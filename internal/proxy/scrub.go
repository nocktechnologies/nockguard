package proxy

import (
	"bytes"
	"container/list"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
)

// scrubSet is an LRU-capped set of secret values with their precomputed encodings.
// It prevents secrets injected during this proxy's lifetime from leaking in
// upstream responses or error messages. The LRU bounds memory to protect against
// denial-of-service via many distinct injected values.
type scrubSet struct {
	mu        sync.Mutex
	maxSize   int                        // max entries; LRU evicts oldest when exceeded
	encodings map[string]*scrubEncodings // value -> precomputed encodings
	lru       *list.List                 // LRU order; element.Value = string (secret value)
}

// scrubEncodings holds all forms of a secret value for substring scrubbing.
type scrubEncodings struct {
	value       string
	jsonEsc     string // JSON-escaped form (without surrounding quotes)
	urlEsc      string // URL-escaped form (percent-encoded)
	urlEscLower string // URL-escaped form with lowercase hex digits
	b64Std      string // base64 standard, padded
	b64StdNp    string // base64 standard, unpadded
	b64URL      string // base64 URL-safe, padded
	b64URLNp    string // base64 URL-safe, unpadded
}

// newScrubSet creates an LRU-bounded scrubbing set capped at maxSize entries.
func newScrubSet(maxSize int) *scrubSet {
	return &scrubSet{
		maxSize:   maxSize,
		encodings: make(map[string]*scrubEncodings),
		lru:       list.New(),
	}
}

// add records a secret value and its precomputed encodings. If the LRU is at
// capacity, the oldest entry is evicted.
// lowercaseHexEscape returns the percent-encoded form with lowercase hex digits.
func lowercaseHexEscape(val string) string {
	var result strings.Builder
	for _, b := range []byte(val) {
		if (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') ||
			b == '-' || b == '_' || b == '.' || b == '~' {
			result.WriteByte(b)
		} else {
			fmt.Fprintf(&result, "%%%02x", b)
		}
	}
	return result.String()
}

func (s *scrubSet) add(val string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// If already present, move to front (most recently used)
	if _, exists := s.encodings[val]; exists {
		elem := s.lru.Front()
		for elem != nil {
			if elem.Value == val {
				s.lru.MoveToFront(elem)
				return
			}
			elem = elem.Next()
		}
		// Shouldn't happen, but if value is in map but not in LRU, add to front
		s.lru.PushFront(val)
		return
	}

	// Evict oldest if at capacity
	if len(s.encodings) >= s.maxSize {
		oldest := s.lru.Back()
		if oldest != nil {
			oldVal := oldest.Value.(string)
			s.lru.Remove(oldest)
			delete(s.encodings, oldVal)
		}
	}

	// Add new value
	enc := &scrubEncodings{
		value:       val,
		jsonEsc:     jsonEscapeWithoutQuotes(val),
		urlEsc:      url.QueryEscape(val),
		urlEscLower: lowercaseHexEscape(val),
		b64Std:      base64.StdEncoding.EncodeToString([]byte(val)),
		b64StdNp:    base64.StdEncoding.WithPadding(base64.NoPadding).EncodeToString([]byte(val)),
		b64URL:      base64.URLEncoding.EncodeToString([]byte(val)),
		b64URLNp:    base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString([]byte(val)),
	}
	s.encodings[val] = enc
	s.lru.PushFront(val)
}

// scrub replaces all occurrences of any tracked secret (in all its encodings)
// with the fixed marker. It operates on a copy to avoid mutating the input.
func (s *scrubSet) scrub(line []byte) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.encodings) == 0 {
		return line
	}

	result := line
	marker := []byte("[nockguard:redacted]")

	for _, enc := range s.encodings {
		// Scrub plaintext
		result = bytes.ReplaceAll(result, []byte(enc.value), marker)
		// Scrub JSON-escaped form
		result = bytes.ReplaceAll(result, []byte(enc.jsonEsc), marker)
		// Scrub URL-escaped forms (both upper and lowercase hex)
		result = bytes.ReplaceAll(result, []byte(enc.urlEsc), marker)
		result = bytes.ReplaceAll(result, []byte(enc.urlEscLower), marker)
		// Scrub all base64 variants
		result = bytes.ReplaceAll(result, []byte(enc.b64Std), marker)
		result = bytes.ReplaceAll(result, []byte(enc.b64StdNp), marker)
		result = bytes.ReplaceAll(result, []byte(enc.b64URL), marker)
		result = bytes.ReplaceAll(result, []byte(enc.b64URLNp), marker)
	}

	return result
}

// jsonEscapeWithoutQuotes returns the JSON-escaped form of a string WITHOUT the
// surrounding double quotes (as json.Marshal would produce them). This is needed
// to scrub the escaped value when it appears embedded in JSON.
func jsonEscapeWithoutQuotes(val string) string {
	b, _ := json.Marshal(val)
	if len(b) >= 2 {
		return string(b[1 : len(b)-1])
	}
	return string(b)
}
