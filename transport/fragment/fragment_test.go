package fragment

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"
)

// recorder captures every Write the fragment layer makes.
type recorder struct {
	net.Conn
	mu     sync.Mutex
	writes [][]byte
}

func (r *recorder) Write(b []byte) (int, error) {
	r.mu.Lock()
	r.writes = append(r.writes, append([]byte(nil), b...))
	r.mu.Unlock()
	return r.Conn.Write(b)
}

func selfSigned(t *testing.T) tls.Certificate {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"},
		DNSNames: []string{"test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestHandshakeThroughFragments(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	srvCfg := &tls.Config{Certificates: []tls.Certificate{selfSigned(t)}}
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		s := tls.Server(c, srvCfg)
		buf := make([]byte, 5)
		if _, err := io.ReadFull(s, buf); err == nil {
			s.Write(buf)
		}
		s.Close()
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	rec := &recorder{Conn: raw}
	cfg, err := New("50-100", "1-2", "3-6")
	if err != nil {
		t.Fatal(err)
	}
	cl := tls.Client(Wrap(rec, cfg), &tls.Config{InsecureSkipVerify: true, ServerName: "test"})
	if _, err := cl.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 5)
	if _, err := io.ReadFull(cl, got); err != nil || string(got) != "hello" {
		t.Fatalf("echo failed: %q %v", got, err)
	}
	cl.Close()

	// The ClientHello must have gone out as 2..6 separate TLS records.
	n := 0
	for _, w := range rec.writes {
		if len(w) >= 5 && w[0] == 0x16 {
			n++
		} else {
			break
		}
	}
	if n < 2 || n > 6 {
		t.Fatalf("expected 2..6 handshake records, got %d (writes=%d)", n, len(rec.writes))
	}
}

func TestDisabled(t *testing.T) {
	cfg, err := New("", "", "")
	if err != nil || cfg != nil {
		t.Fatalf("empty length must disable: %v %v", cfg, err)
	}
	if _, err := New("100-50", "", ""); err == nil {
		t.Fatal("expected error for bad range")
	}
}
