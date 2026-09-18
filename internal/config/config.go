// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

// Package config loads dist defaults, operator config, then secrets.
package config

import (
	"bytes"
	"embed"
	"fmt"
	"strings"
)

//go:embed default-dist
var builtinFS embed.FS

const (
	// DefaultDistPath is the dist defaults file (not a conffile).
	DefaultDistPath = "/usr/lib/bootstash/default-dist"
	// DefaultConfigPath is the operator config file.
	DefaultConfigPath = "/etc/default/bootstash"
	// DefaultSecretsPath is the Google OAuth client JSON (the file
	// the console downloads). Written by bootstash provision-google.
	DefaultSecretsPath = "/etc/bootstash/oidc-google.json"
)

// Config is the merged runtime configuration.
type Config struct {
	PublicURL string
	Binds     []string
	TLSCert   string
	TLSKey    string
	// DisableTLS is TLS=no: TCP binds stay HTTP even if PEMs exist.
	DisableTLS         bool
	CertName           string
	Data               string
	GoogleClientID     string
	GoogleClientSecret string
	CryptoKey          []byte
	PAMService         string
	MaxUpload          int64
	UnixGroup          string
	AdminUsers         []string
	DefaultsPath       string
	ConfigPath         string
	SecretsPath        string
}

var builtin = mustParseBuiltin()

func mustParseBuiltin() map[string][]string {
	b, err := builtinFS.ReadFile("default-dist")
	if err != nil {
		panic("builtin default-dist: " + err.Error())
	}
	m, err := parseReader("<builtin>", bytes.NewReader(b))
	if err != nil {
		panic("builtin default-dist: " + err.Error())
	}
	return m
}

func builtinMap() map[string][]string {
	return cloneMap(builtin)
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// Load merges built-ins, the dist defaults file, then the operator
// config, then the secrets file. A missing file is not an error.
// Secrets do not replace LISTEN.
func Load(defaultsPath, configPath, secretsPath string) (*Config, error) {
	defaultsPath = orDefault(defaultsPath, DefaultDistPath)
	configPath = orDefault(configPath, DefaultConfigPath)
	secretsPath = orDefault(secretsPath, DefaultSecretsPath)
	return load(defaultsPath, configPath, secretsPath)
}

// LoadOperator merges built-ins, dist defaults, and the operator
// file. It does not read the secrets file. User commands that only
// need DATA use this so they can run without OIDC keys.
func LoadOperator(defaultsPath, configPath string) (*Config, error) {
	defaultsPath = orDefault(defaultsPath, DefaultDistPath)
	configPath = orDefault(configPath, DefaultConfigPath)
	cfg, err := load(defaultsPath, configPath, "")
	if err != nil {
		return nil, err
	}
	cfg.SecretsPath = DefaultSecretsPath
	return cfg, nil
}

func load(defaultsPath, configPath, secretsPath string) (*Config, error) {
	merged := builtinMap()
	for _, path := range []string{defaultsPath, configPath} {
		m, err := parseFile(path)
		if err != nil {
			return nil, err
		}
		mergeInto(merged, m)
	}
	if secretsPath != "" {
		sec, err := parseSecrets(secretsPath)
		if err != nil {
			return nil, err
		}
		mergeScalars(merged, sec)
	}

	cfg := &Config{
		DefaultsPath: defaultsPath,
		ConfigPath:   configPath,
		SecretsPath:  secretsPath,
	}
	if err := cfg.apply(merged); err != nil {
		return nil, err
	}
	cfg.deriveCertName()
	cfg.deriveTLSFiles()
	cfg.derivePublicURL()
	return cfg, nil
}

// Ready reports whether the operator has supplied keys required to serve.
func (c *Config) Ready() error {
	if strings.TrimSpace(c.PublicURL) == "" {
		return fmt.Errorf("PUBLIC_URL is not set (write it in %s, or set CERT_NAME / install certs)", c.ConfigPath)
	}
	if strings.TrimSpace(c.GoogleClientID) == "" {
		return fmt.Errorf("OIDC_GOOGLE_CLIENT_ID is not set (install the Google client JSON in %s or run bootstash provision-google)", c.SecretsPath)
	}
	if !c.DisableTLS && (c.TLSCert == "") != (c.TLSKey == "") {
		return fmt.Errorf("TLS_CERT and TLS_KEY must be set together")
	}
	if len(c.Binds) == 0 {
		return fmt.Errorf("no LISTEN specs")
	}
	return nil
}

func (c *Config) apply(m map[string][]string) error {
	c.PublicURL = strings.TrimRight(first(m, "PUBLIC_URL"), "/")
	c.Binds = append([]string(nil), m["LISTEN"]...)
	c.TLSCert = first(m, "TLS_CERT")
	c.TLSKey = first(m, "TLS_KEY")
	c.Data = first(m, "DATA")
	c.GoogleClientID = first(m, "OIDC_GOOGLE_CLIENT_ID")
	c.GoogleClientSecret = first(m, "OIDC_GOOGLE_CLIENT_SECRET")
	c.PAMService = first(m, "PAM_SERVICE")
	c.UnixGroup = first(m, "UNIX_GROUP")

	if s := first(m, "CERT_NAME"); s != "" {
		if badName(s) || !usableOriginHost(s) {
			return fmt.Errorf("CERT_NAME: invalid name %q", s)
		}
		c.CertName = s
	}
	if s := first(m, "TLS"); s != "" {
		off, err := parseTLS(s)
		if err != nil {
			return fmt.Errorf("TLS: %w", err)
		}
		c.DisableTLS = off
	}
	if s := first(m, "MAX_UPLOAD"); s != "" {
		n, err := parseSize(s)
		if err != nil {
			return fmt.Errorf("MAX_UPLOAD: %w", err)
		}
		if n <= 0 {
			return fmt.Errorf("MAX_UPLOAD: must be > 0")
		}
		c.MaxUpload = n
	}
	if s := first(m, "OIDC_CRYPTO"); s != "" {
		key, err := parseCrypto(s)
		if err != nil {
			return fmt.Errorf("OIDC_CRYPTO: %w", err)
		}
		c.CryptoKey = key
	}
	if s := first(m, "ADMIN_USERS"); s != "" {
		users, err := parseAdminUsers(s)
		if err != nil {
			return err
		}
		c.AdminUsers = users
	}
	for _, p := range []struct {
		ok   bool
		name string
	}{
		{c.Data != "", "DATA"},
		{c.PAMService != "", "PAM_SERVICE"},
		{c.UnixGroup != "", "UNIX_GROUP"},
		{c.MaxUpload > 0, "MAX_UPLOAD"},
	} {
		if !p.ok {
			return fmt.Errorf("%s is not set", p.name)
		}
	}
	return nil
}

// UseTLS is HTTPS on TCP binds. False when TLS=no, even if certs exist.
func (c *Config) UseTLS() bool {
	if c == nil || c.DisableTLS {
		return false
	}
	return c.TLSCert != "" && c.TLSKey != ""
}

// IsAdmin reports whether pamUser is in ADMIN_USERS. Empty list: nobody.
// Checked live from the current config (SIGHUP applies). Grants no extra
// HTTP powers in v1; it is the hook for later admin work.
func (c *Config) IsAdmin(pamUser string) bool {
	if c == nil || pamUser == "" {
		return false
	}
	for _, u := range c.AdminUsers {
		if u == pamUser {
			return true
		}
	}
	return false
}

func cloneMap(in map[string][]string) map[string][]string {
	out := make(map[string][]string, len(in))
	for k, v := range in {
		out[k] = append([]string(nil), v...)
	}
	return out
}

func mergeInto(dst, src map[string][]string) {
	if vals, ok := src["LISTEN"]; ok {
		dst["LISTEN"] = append([]string(nil), vals...)
	}
	mergeScalars(dst, src)
}

func mergeScalars(dst, src map[string][]string) {
	for k, vals := range src {
		if k == "LISTEN" || len(vals) == 0 {
			continue
		}
		dst[k] = []string{vals[len(vals)-1]}
	}
}
