// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

// Package configcheck validates operator config + binds + TLS files without listening.
package configcheck

import (
	"crypto/tls"
	"fmt"
	"strings"

	"github.com/nyet/bootstash/internal/bind"
	"github.com/nyet/bootstash/internal/config"
)

// Check loads config, requires Ready keys, parses every LISTEN spec, and
// loads TLS files when configured. It does not bind sockets.
func Check(defaultsPath, configPath, secretsPath string) (*config.Config, error) {
	cfg, err := config.Load(defaultsPath, configPath, secretsPath)
	if err != nil {
		return nil, err
	}
	if err := cfg.Ready(); err != nil {
		return cfg, err
	}
	for _, raw := range cfg.Binds {
		if _, err := bind.ParseSpec(raw); err != nil {
			return cfg, fmt.Errorf("LISTEN %q: %w", raw, err)
		}
	}
	if cfg.UseTLS() {
		if _, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey); err != nil {
			return cfg, fmt.Errorf("TLS_CERT/TLS_KEY: %w", err)
		}
	}
	return cfg, nil
}

// Summary is the check-config / startup line (no secrets).
func Summary(cfg *config.Config) string {
	s := fmt.Sprintf("url=%s listen=%s", cfg.PublicURL, strings.Join(cfg.Binds, ","))
	if cfg.DisableTLS {
		s += " tls=no"
	}
	if len(cfg.AdminUsers) > 0 {
		s += " admins=" + strings.Join(cfg.AdminUsers, ",")
	}
	return s
}
