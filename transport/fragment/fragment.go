// Package fragment splits the first TLS ClientHello record of a connection
// into several smaller TLS records, sent with short pauses between them.
//
// This is the same technique Xray-core calls "fragment" with packets
// "tlshello". Some DPI systems only look at the first TLS record of a
// connection and cannot reassemble a ClientHello spread over several records,
// while every TLS server (Xray REALITY included) reassembles it normally.
// Only the very first write is touched; everything after it is passed
// through unchanged.
package fragment

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Range is an inclusive integer range.
type Range struct{ Min, Max int }

func (r Range) pick() int {
	if r.Max <= r.Min {
		return r.Min
	}
	return r.Min + rand.IntN(r.Max-r.Min+1)
}

// Config describes how to fragment the ClientHello.
type Config struct {
	Length   Range // payload bytes per TLS record
	Interval Range // pause between records, milliseconds
	MaxSplit Range // maximum number of records (0 = unlimited)
}

// ParseRange parses "50-100" or "50".
func ParseRange(s string) (Range, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Range{}, nil
	}
	lo, hi, found := strings.Cut(s, "-")
	a, err := strconv.Atoi(strings.TrimSpace(lo))
	if err != nil || a < 0 {
		return Range{}, fmt.Errorf("invalid range %q", s)
	}
	b := a
	if found {
		b, err = strconv.Atoi(strings.TrimSpace(hi))
		if err != nil || b < a {
			return Range{}, fmt.Errorf("invalid range %q", s)
		}
	}
	return Range{a, b}, nil
}

// New builds a Config from option strings. An empty length means disabled
// and returns nil.
func New(length, interval, maxSplit string) (*Config, error) {
	l, err := ParseRange(length)
	if err != nil {
		return nil, fmt.Errorf("fragment length: %w", err)
	}
	if l.Max == 0 {
		return nil, nil
	}
	if l.Min < 1 {
		return nil, errors.New("fragment length must be at least 1")
	}
	iv, err := ParseRange(interval)
	if err != nil {
		return nil, fmt.Errorf("fragment interval: %w", err)
	}
	ms, err := ParseRange(maxSplit)
	if err != nil {
		return nil, fmt.Errorf("fragment max-split: %w", err)
	}
	return &Config{Length: l, Interval: iv, MaxSplit: ms}, nil
}

// Conn wraps a net.Conn and fragments its first write if it is a TLS
// ClientHello record.
type Conn struct {
	net.Conn
	cfg  *Config
	once sync.Once
	done bool
}

// Wrap returns c unchanged when cfg is nil.
func Wrap(c net.Conn, cfg *Config) net.Conn {
	if cfg == nil || c == nil {
		return c
	}
	return &Conn{Conn: c, cfg: cfg}
}

func (c *Conn) Write(b []byte) (n int, err error) {
	handled := false
	c.once.Do(func() {
		handled = true
		n, err = c.writeFirst(b)
		c.done = true
	})
	if handled {
		return
	}
	return c.Conn.Write(b)
}

func (c *Conn) writeFirst(b []byte) (int, error) {
	// TLS record: type(1)=0x16 handshake, version(2), length(2); then
	// handshake type 0x01 = ClientHello.
	if len(b) < 6 || b[0] != 0x16 || b[1] != 0x03 || b[5] != 0x01 {
		return c.Conn.Write(b)
	}
	recLen := int(b[3])<<8 | int(b[4])
	if 5+recLen > len(b) {
		return c.Conn.Write(b)
	}
	payload := b[5 : 5+recLen]
	rest := b[5+recLen:]

	maxSplit := c.cfg.MaxSplit.pick()
	for off, count := 0, 1; off < len(payload); count++ {
		size := c.cfg.Length.pick()
		if maxSplit > 0 && count >= maxSplit {
			size = len(payload) - off
		}
		if off+size > len(payload) {
			size = len(payload) - off
		}
		rec := make([]byte, 5+size)
		rec[0], rec[1], rec[2] = b[0], b[1], b[2]
		rec[3], rec[4] = byte(size>>8), byte(size)
		copy(rec[5:], payload[off:off+size])
		if _, err := c.Conn.Write(rec); err != nil {
			return 0, err
		}
		off += size
		if off < len(payload) {
			if d := c.cfg.Interval.pick(); d > 0 {
				time.Sleep(time.Duration(d) * time.Millisecond)
			}
		}
	}
	if len(rest) > 0 {
		if _, err := c.Conn.Write(rest); err != nil {
			return 0, err
		}
	}
	return len(b), nil
}

// Upstream lets callers (e.g. Vision) reach the underlying connection.
func (c *Conn) Upstream() any { return c.Conn }

// ReaderReplaceable: reads are never altered.
func (c *Conn) ReaderReplaceable() bool { return true }

// WriterReplaceable: safe once the first write has been handled.
func (c *Conn) WriterReplaceable() bool { return c.done }
