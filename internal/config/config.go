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
	PublicOrigin       string
	Binds              []string
	TLSCert            string
	TLSKey             string
	CertName           string
	Data               string
	GoogleClientID     string
	GoogleClientSecret string
	CryptoKey          []byte
	PAMService         string
	MaxUpload          int64
	SharedWritable     bool
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
// Secrets do not replace BIND.
func Load(defaultsPath, configPath, secretsPath string) (*Config, error) {
	defaultsPath = orDefault(defaultsPath, DefaultDistPath)
	configPath = orDefault(configPath, DefaultConfigPath)
	secretsPath = orDefault(secretsPath, DefaultSecretsPath)

	merged := builtinMap()
	for _, path := range []string{defaultsPath, configPath} {
		m, err := parseFile(path)
		if err != nil {
			return nil, err
		}
		mergeInto(merged, m)
	}
	sec, err := parseSecrets(secretsPath)
	if err != nil {
		return nil, err
	}
	mergeScalars(merged, sec)

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
	cfg.derivePublicOrigin()
	return cfg, nil
}

// Ready reports whether the operator has supplied keys required to serve.
func (c *Config) Ready() error {
	if strings.TrimSpace(c.PublicOrigin) == "" {
		return fmt.Errorf("PUBLIC_ORIGIN is not set (write it in %s, or set CERT_NAME / install certs)", c.ConfigPath)
	}
	if strings.TrimSpace(c.GoogleClientID) == "" {
		return fmt.Errorf("OIDC_GOOGLE_CLIENT_ID is not set (install the Google client JSON in %s or run bootstash provision-google)", c.SecretsPath)
	}
	if (c.TLSCert == "") != (c.TLSKey == "") {
		return fmt.Errorf("TLS_CERT and TLS_KEY must be set together")
	}
	if len(c.Binds) == 0 {
		return fmt.Errorf("no BIND specs")
	}
	return nil
}

func (c *Config) apply(m map[string][]string) error {
	c.PublicOrigin = strings.TrimRight(first(m, "PUBLIC_ORIGIN"), "/")
	c.Binds = append([]string(nil), m["BIND"]...)
	c.TLSCert = first(m, "TLS_CERT")
	c.TLSKey = first(m, "TLS_KEY")
	c.Data = orDefault(first(m, "DATA"), "/var/lib/bootstash")
	c.GoogleClientID = first(m, "OIDC_GOOGLE_CLIENT_ID")
	c.GoogleClientSecret = first(m, "OIDC_GOOGLE_CLIENT_SECRET")
	c.PAMService = orDefault(first(m, "PAM_SERVICE"), "bootstashd")
	c.UnixGroup = orDefault(first(m, "UNIX_GROUP"), "bootstash")

	if s := first(m, "CERT_NAME"); s != "" {
		if badName(s) || !usableOriginHost(s) {
			return fmt.Errorf("CERT_NAME: invalid name %q", s)
		}
		c.CertName = s
	}
	if s := first(m, "SHARED_WRITABLE"); s != "" {
		c.SharedWritable = parseBool(s)
	}
	if s := first(m, "MAX_UPLOAD"); s != "" {
		n, err := parseSize(s)
		if err != nil {
			return fmt.Errorf("MAX_UPLOAD: %w", err)
		}
		c.MaxUpload = n
	}
	if c.MaxUpload == 0 {
		c.MaxUpload = 32 << 20
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
	return nil
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
	if vals, ok := src["BIND"]; ok {
		dst["BIND"] = append([]string(nil), vals...)
	}
	mergeScalars(dst, src)
}

func mergeScalars(dst, src map[string][]string) {
	for k, vals := range src {
		if k == "BIND" || len(vals) == 0 {
			continue
		}
		dst[k] = []string{vals[len(vals)-1]}
	}
}
