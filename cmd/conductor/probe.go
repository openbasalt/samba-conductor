package main

// Health probes for the `healthcheck` command (container images: no shell,
// no openssl). This file is identical in conductor, conductor-idp and
// conductor-sync.

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"
)

// loopbackAddr turns a listen address into one to dial from the same
// network namespace: a wildcard host (":8443", "0.0.0.0:8443", "[::]:8443")
// becomes 127.0.0.1.
func loopbackAddr(listen string) (string, error) {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "", fmt.Errorf("listen address %q: %w", listen, err)
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port), nil
}

// pinnedTLSConfig accepts exactly the leaf certificate in certFile: the
// probe proves that this service answers with its own certificate,
// without a CA, a host name or a "handshake error" line in its log.
func pinnedTLSConfig(certFile string) (*tls.Config, error) {
	raw, err := os.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%s: no PEM certificate", certFile)
	}
	want, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", certFile, err)
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		// The chain is checked by VerifyConnection against the pinned
		// certificate instead of a CA.
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 || !bytes.Equal(cs.PeerCertificates[0].Raw, want.Raw) {
				return errors.New("the listener answered with another certificate")
			}
			return nil
		},
	}, nil
}

// probeTLS completes a TLS handshake with addr, pinned to certFile.
func probeTLS(ctx context.Context, addr, certFile string) error {
	cfg, err := pinnedTLSConfig(certFile)
	if err != nil {
		return err
	}
	d := tls.Dialer{Config: cfg, NetDialer: &net.Dialer{Timeout: 5 * time.Second}}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("TLS %s: %w", addr, err)
	}
	return c.Close()
}

// probeHTTPS GETs path on addr over a TLS connection pinned to certFile and
// expects 200.
func probeHTTPS(ctx context.Context, addr, certFile, path string) error {
	cfg, err := pinnedTLSConfig(certFile)
	if err != nil {
		return err
	}
	tr := &http.Transport{TLSClientConfig: cfg, DisableKeepAlives: true, Proxy: nil}
	defer tr.CloseIdleConnections()
	cl := &http.Client{Transport: tr, Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+addr+path, nil)
	if err != nil {
		return err
	}
	resp, err := cl.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", path, err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", path, resp.Status)
	}
	return nil
}

// probeTCP connects to a plain TCP listener.
func probeTCP(ctx context.Context, addr string) error {
	d := net.Dialer{Timeout: 5 * time.Second}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("TCP %s: %w", addr, err)
	}
	return c.Close()
}

// checkSocket reports whether path is a Unix socket. It does not connect:
// the peers of these sockets are checked by UID, and the probe's own UID
// would be refused (and logged) by design.
func checkSocket(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if st.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("%s is not a socket", path)
	}
	return nil
}
