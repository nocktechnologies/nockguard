package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/nocktechnologies/nockguard/internal/audit"
)

const (
	maxCatalogPages  = 32
	maxCatalogTools  = 4096
	maxCatalogBytes  = 10 << 20
	maxCatalogCursor = 4096
)

type toolObservation struct {
	hash   string
	status string
}

type catalogBuild struct {
	id          uint64
	inFlight    bool
	paginated   bool
	pages       int
	bytes       int
	nextCursor  string
	seenCursors map[string]bool
	tools       map[string]toolObservation
}

type toolCatalog struct {
	mu                 sync.Mutex
	nextID             uint64
	build              *catalogBuild
	published          map[string]toolObservation
	publishedPaginated bool
}

// beginList starts a new generation on a first page. A continuation belongs
// only to the active generation and its exact expected cursor.
func (c *toolCatalog) beginList(params json.RawMessage) uint64 {
	var cursor string
	if len(params) > 0 && string(params) != "null" {
		if validateJSONStringLiterals(params) != nil {
			return 0
		}
		decoder := json.NewDecoder(bytes.NewReader(params))
		decoder.UseNumber()
		value, err := readJCSValue(decoder, 0)
		if err != nil {
			return 0
		}
		if _, err := decoder.Token(); err != io.EOF {
			return 0
		}
		fields, ok := value.(map[string]any)
		if !ok {
			return 0
		}
		for key := range fields {
			if key != "cursor" && strings.EqualFold(key, "cursor") {
				return 0
			}
		}
		if raw, exists := fields["cursor"]; exists {
			var ok bool
			cursor, ok = raw.(string)
			if !ok || cursor == "" || len(cursor) > maxCatalogCursor {
				return 0
			}
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if cursor != "" {
		if c.build != nil && !c.build.inFlight && c.build.nextCursor == cursor {
			c.build.inFlight = true
			return c.build.id
		}
		return 0
	}
	c.nextID++
	c.build = &catalogBuild{id: c.nextID, inFlight: true, seenCursors: make(map[string]bool), tools: make(map[string]toolObservation)}
	// A new listing supersedes the old catalog until it completes.
	c.published = nil
	c.publishedPaginated = false
	return c.build.id
}

func (c *toolCatalog) invalidate() {
	c.mu.Lock()
	c.build = nil
	c.published = nil
	c.publishedPaginated = false
	c.mu.Unlock()
}

func (c *toolCatalog) discard(id uint64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.build != nil && c.build.id == id {
		c.build = nil
		return true
	}
	return false
}

func (c *toolCatalog) observe(name string) toolObservation {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Raw upstream cursors can be reused across builds. Until proxy-owned
	// cursor tokens exist, a paginated chain is not strong enough evidence
	// to bind a later call to that advertised definition.
	if c.publishedPaginated {
		return toolObservation{status: "unobserved"}
	}
	if observation, ok := c.published[name]; ok {
		return observation
	}
	return toolObservation{status: "unobserved"}
}

func (c *toolCatalog) pageWithinBounds(id uint64, size, count int) (active, bounded bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	build := c.build
	if build == nil || build.id != id || !build.inFlight {
		return false, false
	}
	return true, build.pages < maxCatalogPages && build.bytes+size <= maxCatalogBytes &&
		len(build.tools)+count <= maxCatalogTools
}

// addPage commits an entire page under one lock. A failed page discards the
// build, and no partial catalog is ever exposed to a call.
func (c *toolCatalog) addPage(id uint64, size int, observations map[string]toolObservation, nextCursor string) error {
	if id == 0 {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	build := c.build
	if build == nil || build.id != id || !build.inFlight {
		return nil
	}
	discard := func(reason string) error { c.build = nil; return fmt.Errorf("tool catalog %s", reason) }
	if build.pages >= maxCatalogPages || build.bytes+size > maxCatalogBytes || len(build.tools)+len(observations) > maxCatalogTools {
		return discard("bound exceeded")
	}
	if len(nextCursor) > maxCatalogCursor {
		return discard("cursor too long")
	}
	if nextCursor != "" && build.seenCursors[nextCursor] {
		return discard("cursor cycle")
	}
	for name := range observations {
		if _, exists := build.tools[name]; exists {
			return discard("duplicate tool name")
		}
	}
	for name, observation := range observations {
		build.tools[name] = observation
	}
	build.pages++
	build.bytes += size
	build.inFlight = false
	if nextCursor == "" {
		c.published = build.tools
		c.publishedPaginated = build.paginated
		c.build = nil
	} else {
		build.paginated = true
		build.seenCursors[nextCursor] = true
		build.nextCursor = nextCursor
	}
	return nil
}

func pageObservations(tools []json.RawMessage) (map[string]toolObservation, error) {
	observations := make(map[string]toolObservation, len(tools))
	for _, raw := range tools {
		// Extract the exact name independently of digesting so an unhashable
		// definition can still be associated with its advertised name.
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil || fields == nil {
			return nil, fmt.Errorf("malformed tool")
		}
		var name string
		if json.Unmarshal(fields["name"], &name) != nil || name == "" {
			return nil, fmt.Errorf("missing tool name")
		}
		if _, exists := observations[name]; exists {
			return nil, fmt.Errorf("duplicate tool name")
		}
		_, hash, err := digestToolDefinition(raw)
		if err != nil {
			observations[name] = toolObservation{status: "unhashable"}
		} else {
			observations[name] = toolObservation{hash: hash, status: "unpinned"}
		}
	}
	return observations, nil
}

func (p *StdioProxy) applyToolObservation(ev *audit.Event) {
	if ev.SchemaVersion != 2 || ev.Tool == "" {
		return
	}
	observed := p.catalog.observe(ev.Tool)
	if ev.ActionID != "" {
		actual, _ := p.actionObserved.LoadOrStore(ev.ActionID, observed)
		observed = actual.(toolObservation)
	}
	ev.ToolPinStatus = observed.status
	if observed.hash != "" {
		ev.ToolHashVersion = toolHashVersion
		ev.ToolDefinitionHash = observed.hash
	}
}
