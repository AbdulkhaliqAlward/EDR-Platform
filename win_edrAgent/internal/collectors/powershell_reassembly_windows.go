//go:build windows

package collectors

import (
	"fmt"
	"strings"
	"time"
)

type scriptAssembly struct {
	parts        map[int]string
	total, bytes int
	updated      time.Time
}

// PowerShell splits large 4104 records. Keep individual fragments visible,
// and emit the full script on the final fragment so Sigma expressions can
// match content spanning records. Memory is capped at 64 * 512 KiB.
func (c *PowerShellCollector) assembleScript(channel string, pid uint32, id string, part, total int, body string) (string, bool) {
	if total <= 1 {
		return body, true
	}
	if id == "" || total > 64 || part < 1 || part > total {
		return body, false
	}
	c.assemblyMu.Lock()
	defer c.assemblyMu.Unlock()
	if c.assemblies == nil {
		c.assemblies = make(map[string]*scriptAssembly)
	}
	now := time.Now()
	for key, value := range c.assemblies {
		if now.Sub(value.updated) > 2*time.Minute {
			delete(c.assemblies, key)
		}
	}
	key := fmt.Sprintf("%s:%d:%s", channel, pid, id)
	a := c.assemblies[key]
	if a == nil {
		if len(c.assemblies) >= 64 {
			return body, false
		}
		a = &scriptAssembly{parts: map[int]string{}, total: total}
		c.assemblies[key] = a
	}
	if a.total != total {
		delete(c.assemblies, key)
		return body, false
	}
	a.bytes += len(body) - len(a.parts[part])
	if a.bytes > maxScriptBlockChars {
		delete(c.assemblies, key)
		return body, false
	}
	a.parts[part] = body
	a.updated = now
	if len(a.parts) != total {
		return body, false
	}
	var joined strings.Builder
	joined.Grow(a.bytes)
	for i := 1; i <= total; i++ {
		joined.WriteString(a.parts[i])
	}
	delete(c.assemblies, key)
	return joined.String(), true
}
