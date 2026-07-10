package findings

import (
	"sync"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/core"
)

type defaultCollector struct {
	mu       sync.Mutex
	findings []core.Finding
}

// NewCollector returns a thread-safe Collector implementation.
func NewCollector() Collector {
	return &defaultCollector{}
}

func (c *defaultCollector) Add(fs []core.Finding) {
	if len(fs) == 0 {
		return
	}
	c.mu.Lock()
	c.findings = append(c.findings, fs...)
	c.mu.Unlock()
}

func (c *defaultCollector) All() []core.Finding {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]core.Finding, len(c.findings))
	copy(out, c.findings)
	return out
}
