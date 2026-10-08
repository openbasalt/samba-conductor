package main

// Identical in conductor, conductor-idp and conductor-sync (see probe.go).

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeCertPEM(t *testing.T, der []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "cert.pem")
	b := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// selfSigned returns another certificate (httptest servers all share one).
func selfSigned(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "other"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"other"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestProbes(t *testing.T) {
	ctx := context.Background()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			_, _ = w.Write([]byte("ok"))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	addr := srv.Listener.Addr().String()
	cert, otherCert := writeCertPEM(t, srv.Certificate().Raw), writeCertPEM(t, selfSigned(t))

	if err := probeTLS(ctx, addr, cert); err != nil {
		t.Fatalf("pinned handshake: %v", err)
	}
	if err := probeTLS(ctx, addr, otherCert); err == nil || !strings.Contains(err.Error(), "another certificate") {
		t.Fatalf("wrong certificate accepted: %v", err)
	}
	if err := probeHTTPS(ctx, addr, cert, "/healthz"); err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	if err := probeHTTPS(ctx, addr, cert, "/missing"); err == nil {
		t.Fatal("404 accepted")
	}
	if err := probeTCP(ctx, addr); err != nil {
		t.Fatal(err)
	}
}

func TestLoopbackAddr(t *testing.T) {
	for in, want := range map[string]string{":8443": "127.0.0.1:8443", "0.0.0.0:9443": "127.0.0.1:9443",
		"[::]:1": "127.0.0.1:1", "10.0.0.5:8443": "10.0.0.5:8443"} {
		got, err := loopbackAddr(in)
		if err != nil || got != want {
			t.Errorf("loopbackAddr(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := loopbackAddr("8443"); err == nil {
		t.Error("an address without a port was accepted")
	}
}

func TestCheckSocket(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "s.sock")
	if err := checkSocket(sock); err == nil {
		t.Fatal("missing socket accepted")
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	if err := checkSocket(sock); err != nil {
		t.Fatal(err)
	}
	if err := checkSocket(dir); err == nil {
		t.Fatal("a directory was accepted as a socket")
	}
}
