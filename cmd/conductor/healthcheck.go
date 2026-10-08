package main

import (
	"context"
	"flag"
	"fmt"
	"time"

	"github.com/openbasalt/samba-conductor/internal/config"
)

// cmdHealthcheck is the container healthcheck: the web listener answers a
// TLS handshake with conductor's own certificate (a plain TCP connect
// without TLS), and the 2FA socket conductor creates for conductor-idp
// exists when it is enabled. It reads only the configuration: no database,
// no key, no directory access. Exit status 0 = healthy.
func cmdHealthcheck(args []string) error {
	fs := flag.NewFlagSet("healthcheck", flag.ExitOnError)
	cfgPath := fs.String("config", config.DefaultPath, "configuration file")
	timeout := fs.Duration("timeout", 5*time.Second, "overall time limit")
	_ = fs.Parse(args)
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	addr, err := loopbackAddr(cfg.Server.Listen)
	if err != nil {
		return err
	}
	if cfg.TLS() {
		err = probeTLS(ctx, addr, cfg.Server.TLSCert)
	} else {
		err = probeTCP(ctx, addr)
	}
	if err != nil {
		return err
	}
	if cfg.IDP.MFASocket && cfg.IDP.MFASocketPath != "" {
		if err := checkSocket(cfg.IDP.MFASocketPath); err != nil {
			return fmt.Errorf("2FA socket: %w", err)
		}
	}
	fmt.Println("ok")
	return nil
}
