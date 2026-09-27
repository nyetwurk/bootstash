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
	// ProviderGoogle is the only identity provider implemented.
	ProviderGoogle = "google"
)

// Config is the merged runtime configuration.
type Config struct {
	PublicURL string
	Binds     []string
	TLSCert   string
	TLSKey    string
	// DisableTLS is TLS=no: TCP binds stay HTTP even if PEMs exist.
	DisableTLS bool
	// DisableOvpnToken is OVPN_TOKEN=no: do not mint Connect
	// capability URLs or advertise Ovpn-WebAuth. Unset / auto: on.
	DisableOvpnToken   bool
	CertName           string
	Data               string
	GoogleClientID     string
	GoogleClientSecret string
	CryptoKey          []byte
	PAMService         string
	MaxUpload          int64
	UnixGroup          string
	AdminUsers         []string
	// AllowedEmails is the verified-address allowlist. Empty: whoever
	// the OIDC client admits. Each address is one cubby.
	AllowedEmails []string
	// PAM maps a session onto users/<unix name>/. Packaged default
	// is yes. No: email cubbies, and at least one identity provider
	// is required.
	PAM bool
	// IDPs is the identity-provider list when IDPSet is true.
	// Empty with IDPSet means no providers, even if a Google client
	// id is present.
	IDPs []string
	// IDPSet is true when an IDP= line was present. False means
	// auto: google when GoogleClientID is set, otherwise none.
	IDPSet       bool
	DefaultsPath string
	ConfigPath   string
	SecretsPath  string
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
		// Operator keys. A KEY=value secrets file cannot flip them.
		delete(sec, "PAM")
		delete(sec, "IDP")
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

// Providers is the resolved identity-provider list. When IDP was
// not set, Google is included only if a client id is configured.
func (c *Config) Providers() []string {
	if c == nil {
		return nil
	}
	if c.IDPSet {
		return append([]string(nil), c.IDPs...)
	}
	if strings.TrimSpace(c.GoogleClientID) != "" {
		return []string{ProviderGoogle}
	}
	return nil
}

// LinkPAM reports whether an identity-provider auth must still log in
// with a Unix password before it can open users/<name>/.
func (c *Config) LinkPAM() bool {
	return c != nil && c.PAM && len(c.Providers()) > 0
}

// PAMLogin reports whether /login is a Unix username and password.
// That is PAM cubbies with no identity provider configured.
func (c *Config) PAMLogin() bool {
	return c != nil && c.PAM && len(c.Providers()) == 0
}

// Ready reports whether the operator has supplied keys required to serve.
func (c *Config) Ready() error {
	if strings.TrimSpace(c.PublicURL) == "" {
		return fmt.Errorf("PUBLIC_URL is not set (write it in %s, or set CERT_NAME / install certs)", c.ConfigPath)
	}
	for _, name := range c.Providers() {
		if name != ProviderGoogle {
			return fmt.Errorf("IDP: unknown provider %q", name)
		}
		if strings.TrimSpace(c.GoogleClientID) == "" {
			return fmt.Errorf("OIDC_GOOGLE_CLIENT_ID is not set (install the Google client JSON in %s or run bootstash provision-google)", c.SecretsPath)
		}
	}
	if !c.PAM && len(c.Providers()) == 0 {
		return fmt.Errorf("PAM=no requires an identity provider (set IDP=google and install the Google client JSON in %s, or run bootstash provision-google)", c.SecretsPath)
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
		off, err := parseAutoOff(s)
		if err != nil {
			return fmt.Errorf("TLS: %w", err)
		}
		c.DisableTLS = off
	}
	if s := first(m, "OVPN_TOKEN"); s != "" {
		off, err := parseAutoOff(s)
		if err != nil {
			return fmt.Errorf("OVPN_TOKEN: %w", err)
		}
		c.DisableOvpnToken = off
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
	emails, err := parseAllowedEmails(m["ALLOWED_EMAILS"])
	if err != nil {
		return err
	}
	c.AllowedEmails = emails
	c.PAM = true
	if s := first(m, "PAM"); s != "" {
		on, err := parseBool(s)
		if err != nil {
			return fmt.Errorf("PAM: %w", err)
		}
		c.PAM = on
	}
	if vals, ok := m["IDP"]; ok {
		names, err := parseIDPNames(vals)
		if err != nil {
			return err
		}
		c.IDPSet = true
		c.IDPs = names
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
// HTTP powers currently; it is the hook for later admin work.
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
	// Every ALLOWED_EMAILS line counts. Mentioning the key replaces
	// the packaged list, the same way LISTEN does.
	if vals, ok := src["ALLOWED_EMAILS"]; ok {
		dst["ALLOWED_EMAILS"] = append([]string(nil), vals...)
	}
	if vals, ok := src["IDP"]; ok {
		dst["IDP"] = append([]string(nil), vals...)
	}
	mergeScalars(dst, src)
}

func mergeScalars(dst, src map[string][]string) {
	for k, vals := range src {
		if k == "LISTEN" || k == "ALLOWED_EMAILS" || k == "IDP" || len(vals) == 0 {
			continue
		}
		dst[k] = []string{vals[len(vals)-1]}
	}
}
