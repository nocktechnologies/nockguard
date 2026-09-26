package ratelimit

import (
	"sync"
	"testing"
	"time"
)

// A hosted gateway creates session gates while other sessions use the shared
// limiter. WithTrust installs the callback during each gate's construction.
func TestConcurrentSessionConfiguration(t *testing.T) {
	l := New(Config{MaxCalls: 100, Window: time.Minute})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			l.WithMaxCallsFunc(func(n int) int { return n })
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			l.Allow()
		}
	}()
	wg.Wait()
	if _, ok := l.Allow(); ok {
		t.Fatal("shared limit was reset by session configuration")
	}
}
