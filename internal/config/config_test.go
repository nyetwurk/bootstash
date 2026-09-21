// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadOperatorConfigReplacesLISTEN(t *testing.T) {
	dir := t.TempDir()
	def := filepath.Join(dir, "default-dist")
	op := filepath.Join(dir, "config")
	if err := os.WriteFile(def, []byte("LISTEN=127.0.0.1:8080\nDATA=/tmp/data\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(op, []byte("LISTEN=tun0:8443\nLISTEN=lo:8080\nPUBLIC_URL=https://stash.test\nOIDC_GOOGLE_CLIENT_ID=cid\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(def, op, filepath.Join(dir, "nosecrets"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(cfg.Binds, ","); got != "tun0:8443,lo:8080" {
		t.Fatalf("binds %q", got)
	}
	if err := cfg.Ready(); err != nil {
		t.Fatal(err)
	}
}

func TestLoadMissingConfigKeepsDefaultLISTEN(t *testing.T) {
	dir := t.TempDir()
	def := filepath.Join(dir, "default-dist")
	if err := os.WriteFile(def, []byte("LISTEN=127.0.0.1:8080\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(def, filepath.Join(dir, "missing"), filepath.Join(dir, "nosecrets"))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Binds) != 1 || cfg.Binds[0] != "127.0.0.1:8080" {
		t.Fatalf("binds %#v", cfg.Binds)
	}
	if err := cfg.Ready(); err == nil {
		t.Fatal("expected Ready error without OIDC_GOOGLE_CLIENT_ID")
	}
}

func TestDefaultPublicURLFromHostname(t *testing.T) {
	prev := lookupFQDN
	t.Cleanup(func() { lookupFQDN = prev })
	lookupFQDN = func() (string, error) { return "box.example", nil }

	dir := t.TempDir()
	def := filepath.Join(dir, "default-dist")
	if err := os.WriteFile(def, []byte("LISTEN=127.0.0.1:8080\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(def, filepath.Join(dir, "missing"), filepath.Join(dir, "nosecrets"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PublicURL != "http://box.example:8080" {
		t.Fatalf("origin %q", cfg.PublicURL)
	}

	op := filepath.Join(dir, "tls")
	if err := os.WriteFile(op, []byte("TLS_CERT=/c\nTLS_KEY=/k\nLISTEN=*:443\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err = Load(def, op, filepath.Join(dir, "nosecrets"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PublicURL != "https://box.example" {
		t.Fatalf("tls origin %q", cfg.PublicURL)
	}

	explicit := filepath.Join(dir, "explicit")
	if err := os.WriteFile(explicit, []byte("PUBLIC_URL=https://stash.test\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err = Load(def, explicit, filepath.Join(dir, "nosecrets"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PublicURL != "https://stash.test" {
		t.Fatalf("explicit origin %q", cfg.PublicURL)
	}

	lookupFQDN = func() (string, error) { return "localhost", nil }
	cfg, err = Load(def, filepath.Join(dir, "missing"), filepath.Join(dir, "nosecrets"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PublicURL != "" {
		t.Fatalf("localhost origin %q", cfg.PublicURL)
	}
}

func TestDefaultTLSFromCertDir(t *testing.T) {
	prevFQDN := lookupFQDN
	prevRoot := certRoot
	t.Cleanup(func() {
		lookupFQDN = prevFQDN
		certRoot = prevRoot
	})
	lookupFQDN = func() (string, error) { return "box.example", nil }
	root := t.TempDir()
	certRoot = root
	hostDir := filepath.Join(root, "box.example")
	if err := os.Mkdir(hostDir, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hostDir, "fullchain.pem"), []byte("c"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hostDir, "privkey.pem"), []byte("k"), 0640); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	def := filepath.Join(dir, "default-dist")
	if err := os.WriteFile(def, []byte("LISTEN=127.0.0.1:8080\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(def, filepath.Join(dir, "missing"), filepath.Join(dir, "nosecrets"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TLSCert != filepath.Join(hostDir, "fullchain.pem") || cfg.TLSKey != filepath.Join(hostDir, "privkey.pem") {
		t.Fatalf("tls %q %q", cfg.TLSCert, cfg.TLSKey)
	}
	if cfg.PublicURL != "https://box.example:8080" {
		t.Fatalf("origin %q", cfg.PublicURL)
	}
	if !cfg.UseTLS() {
		t.Fatal("expected UseTLS")
	}

	off := filepath.Join(dir, "tls-off")
	if err := os.WriteFile(off, []byte("TLS=0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err = Load(def, off, filepath.Join(dir, "nosecrets"))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.DisableTLS || cfg.UseTLS() {
		t.Fatalf("tls off %+v", cfg)
	}
	if cfg.TLSCert == "" {
		t.Fatal("certs still discovered")
	}
	if cfg.PublicURL != "http://box.example:8080" {
		t.Fatalf("derived url %q", cfg.PublicURL)
	}

	keep := filepath.Join(dir, "tls-off-url")
	if err := os.WriteFile(keep, []byte("TLS=0\nPUBLIC_URL=https://stash.test\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err = Load(def, keep, filepath.Join(dir, "nosecrets"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.UseTLS() || cfg.PublicURL != "https://stash.test" {
		t.Fatalf("explicit https url with tls off %+v", cfg)
	}

	explicit := filepath.Join(dir, "explicit")
	if err := os.WriteFile(explicit, []byte("TLS_CERT=/c\nTLS_KEY=/k\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err = Load(def, explicit, filepath.Join(dir, "nosecrets"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TLSCert != "/c" || cfg.TLSKey != "/k" {
		t.Fatalf("explicit tls %q %q", cfg.TLSCert, cfg.TLSKey)
	}
}

func TestDefaultTLSFromCertName(t *testing.T) {
	prevFQDN := lookupFQDN
	prevRoot := certRoot
	t.Cleanup(func() {
		lookupFQDN = prevFQDN
		certRoot = prevRoot
	})
	lookupFQDN = func() (string, error) { return "box.internal.example", nil }
	root := t.TempDir()
	certRoot = root
	hostDir := filepath.Join(root, "box.example")
	if err := os.Mkdir(hostDir, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hostDir, "fullchain.pem"), []byte("c"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hostDir, "privkey.pem"), []byte("k"), 0640); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	def := filepath.Join(dir, "default-dist")
	op := filepath.Join(dir, "config")
	if err := os.WriteFile(def, []byte("LISTEN=127.0.0.1:8080\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(op, []byte("CERT_NAME=box.example\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(def, op, filepath.Join(dir, "nosecrets"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TLSCert != filepath.Join(hostDir, "fullchain.pem") {
		t.Fatalf("tls %q", cfg.TLSCert)
	}
	if cfg.PublicURL != "https://box.example:8080" {
		t.Fatalf("origin %q", cfg.PublicURL)
	}
}

func TestDefaultOriginFromOnlyCertDir(t *testing.T) {
	prevFQDN := lookupFQDN
	prevRoot := certRoot
	t.Cleanup(func() {
		lookupFQDN = prevFQDN
		certRoot = prevRoot
	})
	lookupFQDN = func() (string, error) { return "box.internal.example", nil }
	root := t.TempDir()
	certRoot = root
	hostDir := filepath.Join(root, "box.example")
	if err := os.Mkdir(hostDir, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hostDir, "fullchain.pem"), []byte("c"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hostDir, "privkey.pem"), []byte("k"), 0640); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	def := filepath.Join(dir, "default-dist")
	if err := os.WriteFile(def, []byte("LISTEN=127.0.0.1:8080\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(def, filepath.Join(dir, "missing"), filepath.Join(dir, "nosecrets"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CertName != "box.example" {
		t.Fatalf("cert name %q", cfg.CertName)
	}
	if cfg.PublicURL != "https://box.example:8080" {
		t.Fatalf("origin %q", cfg.PublicURL)
	}
}

func TestParseSize(t *testing.T) {
	n, err := parseSize("32MiB")
	if err != nil || n != 32<<20 {
		t.Fatalf("32MiB -> %d %v", n, err)
	}
}

func TestCommentsAndQuotes(t *testing.T) {
	dir := t.TempDir()
	ov := filepath.Join(dir, "ov")
	body := "# comment\nPUBLIC_URL=\"https://stash.test\"\nOIDC_GOOGLE_CLIENT_ID=abc\n"
	if err := os.WriteFile(ov, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(filepath.Join(dir, "nope"), ov, filepath.Join(dir, "nosecrets"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PublicURL != "https://stash.test" || cfg.GoogleClientID != "abc" {
		t.Fatalf("%+v", cfg)
	}
}

func TestAdminUsers(t *testing.T) {
	dir := t.TempDir()
	ov := filepath.Join(dir, "ov")
	body := "PUBLIC_URL=https://stash.test\nOIDC_GOOGLE_CLIENT_ID=cid\nADMIN_USERS=alice, bob\n"
	if err := os.WriteFile(ov, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(filepath.Join(dir, "nope"), ov, filepath.Join(dir, "nosecrets"))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.IsAdmin("alice") || !cfg.IsAdmin("bob") || cfg.IsAdmin("carol") || cfg.IsAdmin("") {
		t.Fatalf("admins %#v", cfg.AdminUsers)
	}
	bad := filepath.Join(dir, "bad")
	if err := os.WriteFile(bad, []byte("ADMIN_USERS=../root\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(filepath.Join(dir, "nope"), bad, filepath.Join(dir, "nosecrets")); err == nil {
		t.Fatal("expected invalid ADMIN_USERS")
	}
}

func TestLoadOperatorSkipsSecrets(t *testing.T) {
	dir := t.TempDir()
	def := filepath.Join(dir, "default-dist")
	op := filepath.Join(dir, "config")
	sec := filepath.Join(dir, "oidc-google.json")
	if err := os.WriteFile(def, []byte("LISTEN=127.0.0.1:8080\nDATA=/tmp/data\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(op, []byte("DATA=/var/lib/bootstash\nPUBLIC_URL=https://stash.test\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sec, []byte(`{"web":{"client_id":"hidden","client_secret":"sekrit"}}`+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(def, op, sec)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.GoogleClientID != "hidden" {
		t.Fatalf("Load id %q", loaded.GoogleClientID)
	}
	cfg, err := LoadOperator(def, op)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Data != "/var/lib/bootstash" {
		t.Fatalf("data %q", cfg.Data)
	}
	if cfg.GoogleClientID != "" {
		t.Fatalf("must not read secrets, got %q", cfg.GoogleClientID)
	}
}

func TestLoadSecretsOverridesOIDCIgnoresLISTEN(t *testing.T) {
	dir := t.TempDir()
	def := filepath.Join(dir, "default-dist")
	op := filepath.Join(dir, "config")
	sec := filepath.Join(dir, "oidc-google")
	if err := os.WriteFile(def, []byte("LISTEN=127.0.0.1:8080\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(op, []byte("PUBLIC_URL=https://stash.test\nOIDC_GOOGLE_CLIENT_ID=old\nLISTEN=lo:8080\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sec, []byte(`{"web":{"client_id":"new","client_secret":"sekrit"},"LISTEN":"evil:9"}`+"\n"), 0640); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(def, op, sec)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(cfg.Binds, ","); got != "lo:8080" {
		t.Fatalf("binds %q", got)
	}
	if cfg.GoogleClientID != "new" || cfg.GoogleClientSecret != "sekrit" {
		t.Fatalf("oidc %+v", cfg)
	}
	if cfg.SecretsPath != sec {
		t.Fatalf("secrets path %q", cfg.SecretsPath)
	}
}

func TestParseGoogleClientJSON(t *testing.T) {
	id, secret, err := ParseGoogleClientJSON([]byte(`{"web":{"client_id":" a ","client_secret":"s"}}`))
	if err != nil || id != "a" || secret != "s" {
		t.Fatalf("%q %q %v", id, secret, err)
	}
	if _, _, err := ParseGoogleClientJSON([]byte(`{"installed":{"client_id":"a","client_secret":"s"}}`)); err == nil {
		t.Fatal("expected desktop JSON error")
	}
}

func TestLoadSecretsKEYValueFallback(t *testing.T) {
	dir := t.TempDir()
	def := filepath.Join(dir, "default-dist")
	sec := filepath.Join(dir, "oidc-google")
	if err := os.WriteFile(def, []byte("LISTEN=127.0.0.1:8080\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sec, []byte("OIDC_GOOGLE_CLIENT_ID=legacy\n"), 0640); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(def, filepath.Join(dir, "missing"), sec)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.GoogleClientID != "legacy" {
		t.Fatalf("id %q", cfg.GoogleClientID)
	}
}

func TestParseBoolPairs(t *testing.T) {
	for _, s := range []string{"1", "true", "yes", "on", "TRUE", "Yes"} {
		v, err := parseBool(s)
		if err != nil || !v {
			t.Fatalf("%q -> %v %v", s, v, err)
		}
	}
	for _, s := range []string{"0", "false", "no", "off", "FALSE", "No"} {
		v, err := parseBool(s)
		if err != nil || v {
			t.Fatalf("%q -> %v %v", s, v, err)
		}
	}
	if _, err := parseBool("maybe"); err == nil {
		t.Fatal("expected error")
	}
}

func TestTLSFalseSynonym(t *testing.T) {
	dir := t.TempDir()
	def := filepath.Join(dir, "default-dist")
	op := filepath.Join(dir, "config")
	if err := os.WriteFile(def, []byte("LISTEN=127.0.0.1:8080\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(op, []byte("TLS=false\nPUBLIC_URL=http://box.example:8080\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(def, op, filepath.Join(dir, "nosecrets"))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.DisableTLS || cfg.UseTLS() {
		t.Fatalf("%+v", cfg)
	}
	if err := os.WriteFile(op, []byte("TLS=maybe\nPUBLIC_URL=http://box.example:8080\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err = Load(def, op, filepath.Join(dir, "nosecrets"))
	if err != nil || cfg.DisableTLS {
		t.Fatalf("maybe: %+v %v", cfg, err)
	}
	if err := os.WriteFile(op, []byte("TLS=sometimes\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(def, op, filepath.Join(dir, "nosecrets")); err == nil {
		t.Fatal("expected TLS=sometimes to fail")
	}
}

func TestBuiltinDefaultDist(t *testing.T) {
	prevFQDN := lookupFQDN
	prevRoot := certRoot
	t.Cleanup(func() {
		lookupFQDN = prevFQDN
		certRoot = prevRoot
	})
	lookupFQDN = func() (string, error) { return "localhost", nil }
	certRoot = t.TempDir()

	dir := t.TempDir()
	cfg, err := Load(filepath.Join(dir, "missing-dist"), filepath.Join(dir, "missing-op"), filepath.Join(dir, "nosecrets"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Data != "/var/lib/bootstash" || cfg.PAMService != "bootstashd" || cfg.UnixGroup != "bootstash" {
		t.Fatalf("paths %+v", cfg)
	}
	if cfg.MaxUpload != 32<<20 || cfg.DisableTLS {
		t.Fatalf("scalars %+v", cfg)
	}
	if len(cfg.Binds) != 1 || cfg.Binds[0] != "127.0.0.1:8080" {
		t.Fatalf("binds %#v", cfg.Binds)
	}
	if cfg.PublicURL != "" || cfg.CertName != "" || cfg.TLSCert != "" || cfg.GoogleClientID != "" {
		t.Fatalf("empty %+v", cfg)
	}

	for _, key := range []string{"OIDC_GOOGLE_CLIENT_ID", "OIDC_GOOGLE_CLIENT_SECRET", "OIDC_CRYPTO"} {
		if _, ok := builtin[key]; ok {
			t.Fatalf("default-dist must not set %s", key)
		}
	}
}
