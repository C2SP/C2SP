package main

import "sync"

// maxCachedPages bounds the page cache, since @commit URLs can reference an
// unbounded number of pages.
const maxCachedPages = 1024

// pageCache holds rendered pages, invalidated as a whole whenever the
// repository generation changes: even pages for immutable tags depend on
// movable state, such as the latest version and the maintainers list.
type pageCache struct {
	mu    sync.Mutex
	gen   uint64
	pages map[string][]byte
}

func (c *pageCache) get(key string, gen uint64) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.gen != gen {
		return nil, false
	}
	page, ok := c.pages[key]
	return page, ok
}

func (c *pageCache) put(key string, gen uint64, page []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.gen != gen || c.pages == nil {
		c.gen = gen
		c.pages = make(map[string][]byte)
	}
	if len(c.pages) >= maxCachedPages {
		clear(c.pages)
	}
	c.pages[key] = page
}
