package gotr4

import (
	"crypto/rand"
	"io"
)

func (c *conversation) RandReader() io.Reader {
	if c.r != nil {
		return c.r
	}
	return rand.Reader
}
