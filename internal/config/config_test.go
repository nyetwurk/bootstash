// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadOperatorConfigReplacesBIND(t *testing.T) {
	dir := t.TempDir()
	def := filepath.Join(dir, "defaults.conf")
	op := filepath.Join(dir, "config")
	if err := os.WriteFile(def, []byte("BIND=127.0.0.1:8080\nDATA=/tmp/data\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(op, []byte("BIND=tun0:8443\nBIND=lo:8080\nPUBLIC_ORIGIN=https://stash.test\nOIDC_GOOGLE_CLIENT_ID=cid\n"), 0600); err != nil {
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

func TestLoadMissingConfigKeepsDefaultBIND(t *testing.T) {
	dir := t.TempDir()
	def := filepath.Join(dir, "defaults.conf")
	if err := os.WriteFile(def, []byte("BIND=127.0.0.1:8080\n"), 0644); err != nil {
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
		t.Fatal("expected Ready error without PUBLIC_ORIGIN")
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
	body := "# comment\nPUBLIC_ORIGIN=\"https://stash.test\"\nOIDC_GOOGLE_CLIENT_ID=abc\n"
	if err := os.WriteFile(ov, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(filepath.Join(dir, "nope"), ov, filepath.Join(dir, "nosecrets"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PublicOrigin != "https://stash.test" || cfg.GoogleClientID != "abc" {
		t.Fatalf("%+v", cfg)
	}
}

func TestAdminUsers(t *testing.T) {
	dir := t.TempDir()
	ov := filepath.Join(dir, "ov")
	body := "PUBLIC_ORIGIN=https://stash.test\nOIDC_GOOGLE_CLIENT_ID=cid\nADMIN_USERS=alice, bob\n"
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

func TestLoadSecretsOverridesOIDCIgnoresBIND(t *testing.T) {
	dir := t.TempDir()
	def := filepath.Join(dir, "defaults.conf")
	op := filepath.Join(dir, "config")
	sec := filepath.Join(dir, "oidc-google")
	if err := os.WriteFile(def, []byte("BIND=127.0.0.1:8080\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(op, []byte("PUBLIC_ORIGIN=https://stash.test\nOIDC_GOOGLE_CLIENT_ID=old\nBIND=lo:8080\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sec, []byte("BIND=evil:9\nOIDC_GOOGLE_CLIENT_ID=new\nOIDC_GOOGLE_CLIENT_SECRET=sekrit\n"), 0640); err != nil {
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
