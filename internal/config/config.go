// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

// Package config loads packaged defaults, operator config, then secrets.
package config

import (
	"bufio"
	"bytes"
	"embed"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"unicode"
)

//go:embed defaults.conf
var builtinFS embed.FS

const (
	// DefaultDefaultsPath is the packaged defaults file.
	DefaultDefaultsPath = "/usr/lib/bootstash/defaults.conf"
	// DefaultConfigPath is the operator config file (empty on install).
	DefaultConfigPath = "/etc/default/bootstash"
	// DefaultSecretsPath is Google OIDC client id/secret. Written by
	// bootstash provision-google, not by the operator config file.
	DefaultSecretsPath = "/etc/bootstash/oidc-google"
)

// Config is the merged runtime configuration.
type Config struct {
	PublicOrigin       string
	Binds              []string
	TLSCert            string
	TLSKey             string
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

// BuiltinMap is compiled-in defaults (internal/config/defaults.conf)
// used when the packaged file is absent.
func BuiltinMap() map[string][]string {
	b, err := builtinFS.ReadFile("defaults.conf")
	if err != nil {
		panic("builtin defaults: " + err.Error())
	}
	m, err := parseReader("<builtin>", bytes.NewReader(b))
	if err != nil {
		panic("builtin defaults: " + err.Error())
	}
	return m
}

// Load merges built-ins, the packaged defaults file, then the operator
// config, then the secrets file. A missing file is not an error.
// Secrets do not replace BIND.
func Load(defaultsPath, configPath, secretsPath string) (*Config, error) {
	if defaultsPath == "" {
		defaultsPath = DefaultDefaultsPath
	}
	if configPath == "" {
		configPath = DefaultConfigPath
	}
	if secretsPath == "" {
		secretsPath = DefaultSecretsPath
	}
	merged := cloneMap(BuiltinMap())
	def, err := parseFile(defaultsPath)
	if err != nil {
		return nil, err
	}
	mergeInto(merged, def)
	op, err := parseFile(configPath)
	if err != nil {
		return nil, err
	}
	mergeInto(merged, op)
	sec, err := parseFile(secretsPath)
	if err != nil {
		return nil, err
	}
	mergeSecrets(merged, sec)

	cfg := &Config{
		DefaultsPath: defaultsPath,
		ConfigPath:   configPath,
		SecretsPath:  secretsPath,
	}
	if err := cfg.apply(merged); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Ready reports whether the operator has supplied keys required to serve.
func (c *Config) Ready() error {
	if strings.TrimSpace(c.PublicOrigin) == "" {
		return fmt.Errorf("PUBLIC_ORIGIN is not set (write it in %s)", c.ConfigPath)
	}
	if strings.TrimSpace(c.GoogleClientID) == "" {
		return fmt.Errorf("OIDC_GOOGLE_CLIENT_ID is not set (write it in %s or run bootstash provision-google)", c.SecretsPath)
	}
	if c.TLSCert != "" && c.TLSKey == "" || c.TLSCert == "" && c.TLSKey != "" {
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
	c.Data = first(m, "DATA")
	c.GoogleClientID = first(m, "OIDC_GOOGLE_CLIENT_ID")
	c.GoogleClientSecret = first(m, "OIDC_GOOGLE_CLIENT_SECRET")
	c.PAMService = first(m, "PAM_SERVICE")
	c.UnixGroup = first(m, "UNIX_GROUP")
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
	if s := first(m, "OIDC_CRYPTO"); s != "" {
		key, err := parseCrypto(s)
		if err != nil {
			return fmt.Errorf("OIDC_CRYPTO: %w", err)
		}
		c.CryptoKey = key
	}
	if c.PAMService == "" {
		c.PAMService = "bootstashd"
	}
	if c.Data == "" {
		c.Data = "/var/lib/bootstash"
	}
	if c.UnixGroup == "" {
		c.UnixGroup = "bootstash"
	}
	if c.MaxUpload == 0 {
		c.MaxUpload = 32 << 20
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

func mergeSecrets(dst, src map[string][]string) {
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

func parseFile(path string) (map[string][]string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return make(map[string][]string), nil
		}
		return nil, err
	}
	defer f.Close()
	return parseReader(path, f)
}

func parseReader(origin string, r io.Reader) (map[string][]string, error) {
	out := make(map[string][]string)
	sc := bufio.NewScanner(r)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("%s:%d: expected KEY=value", origin, lineNo)
		}
		key = strings.TrimSpace(key)
		if !validKey(key) {
			return nil, fmt.Errorf("%s:%d: invalid key %q", origin, lineNo, key)
		}
		val = unquote(strings.TrimSpace(val))
		out[key] = append(out[key], val)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func validKey(k string) bool {
	if k == "" {
		return false
	}
	for i, r := range k {
		if i == 0 {
			if r < 'A' || r > 'Z' {
				return false
			}
			continue
		}
		if (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '_' {
			return false
		}
	}
	return true
}

func unquote(s string) string {
	if len(s) >= 2 {
		if s[0] == '"' && s[len(s)-1] == '"' {
			return strings.ReplaceAll(s[1:len(s)-1], `\"`, `"`)
		}
		if s[0] == '\'' && s[len(s)-1] == '\'' {
			return s[1 : len(s)-1]
		}
	}
	return s
}

func first(m map[string][]string, k string) string {
	v := m[k]
	if len(v) == 0 {
		return ""
	}
	return v[len(v)-1]
}

func parseAdminUsers(s string) ([]string, error) {
	var out []string
	for _, p := range strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || unicode.IsSpace(r)
	}) {
		if p == "" {
			continue
		}
		if strings.ContainsAny(p, "/\\:\x00") || p == "." || p == ".." {
			return nil, fmt.Errorf("ADMIN_USERS: invalid name %q", p)
		}
		out = append(out, p)
	}
	return out, nil
}

func parseBool(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func parseSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	mult := int64(1)
	upper := strings.ToUpper(s)
	switch {
	case strings.HasSuffix(upper, "KIB"):
		mult, s = 1024, s[:len(s)-3]
	case strings.HasSuffix(upper, "MIB"):
		mult, s = 1024*1024, s[:len(s)-3]
	case strings.HasSuffix(upper, "GIB"):
		mult, s = 1024*1024*1024, s[:len(s)-3]
	case strings.HasSuffix(upper, "KB"):
		mult, s = 1000, s[:len(s)-2]
	case strings.HasSuffix(upper, "MB"):
		mult, s = 1000*1000, s[:len(s)-2]
	case strings.HasSuffix(upper, "GB"):
		mult, s = 1000*1000*1000, s[:len(s)-2]
	case len(upper) > 0 && (upper[len(upper)-1] == 'K' || upper[len(upper)-1] == 'M' || upper[len(upper)-1] == 'G'):
		switch upper[len(upper)-1] {
		case 'K':
			mult = 1024
		case 'M':
			mult = 1024 * 1024
		case 'G':
			mult = 1024 * 1024 * 1024
		}
		s = s[:len(s)-1]
	}
	s = strings.TrimSpace(s)
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, err
	}
	if n < 0 {
		return 0, fmt.Errorf("negative size")
	}
	return n * mult, nil
}

func parseCrypto(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if isHex(s) && len(s)%2 == 0 {
		b, err := hex.DecodeString(s)
		if err != nil {
			return nil, err
		}
		if len(b) < 32 {
			return nil, fmt.Errorf("need at least 32 bytes")
		}
		return b, nil
	}
	if len(s) < 32 {
		return nil, fmt.Errorf("need at least 32 bytes")
	}
	return []byte(s), nil
}

func isHex(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !unicode.Is(unicode.ASCII_Hex_Digit, r) {
			return false
		}
	}
	return true
}
