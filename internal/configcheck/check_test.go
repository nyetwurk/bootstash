// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package configcheck

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nyet/bootstash/internal/config"
)

func TestCheckReadyAndListen(t *testing.T) {
	dir := t.TempDir()
	ov := filepath.Join(dir, "config")
	body := "PUBLIC_URL=https://stash.test\nOIDC_GOOGLE_CLIENT_ID=cid\nLISTEN=127.0.0.1:8080\n"
	if err := os.WriteFile(ov, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Check("", ov, filepath.Join(dir, "nosecrets"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PublicURL != "https://stash.test" {
		t.Fatalf("%+v", cfg)
	}
}

func TestSummaryIncludesAdmins(t *testing.T) {
	cfg := &config.Config{PublicURL: "https://stash.test", Binds: []string{"127.0.0.1:8080"}, AdminUsers: []string{"alice"}}
	got := Summary(cfg)
	if !strings.Contains(got, "admins=alice") || !strings.Contains(got, "listen=127.0.0.1:8080") {
		t.Fatalf("%s", got)
	}
	off := &config.Config{PublicURL: "http://stash.test", Binds: []string{"127.0.0.1:8080"}, DisableTLS: true, DisableOvpnToken: true}
	got = Summary(off)
	if !strings.Contains(got, "tls=no") || !strings.Contains(got, "ovpn-token=no") {
		t.Fatalf("%s", got)
	}
}

func TestCheckBadListen(t *testing.T) {
	dir := t.TempDir()
	ov := filepath.Join(dir, "config")
	body := "PUBLIC_URL=https://stash.test\nOIDC_GOOGLE_CLIENT_ID=cid\nLISTEN=127.0.0.1:0\n"
	if err := os.WriteFile(ov, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Check("", ov, filepath.Join(dir, "nosecrets")); err == nil {
		t.Fatal("expected port 0 to fail")
	}
}

func TestCheckMissingOrigin(t *testing.T) {
	dir := t.TempDir()
	ov := filepath.Join(dir, "config")
	// Unix-only LISTEN has no TCP port, so hostname -f cannot fill PUBLIC_URL.
	if err := os.WriteFile(ov, []byte("OIDC_GOOGLE_CLIENT_ID=cid\nLISTEN=unix:///tmp/bootstash.sock\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Check("", ov, filepath.Join(dir, "nosecrets")); err == nil {
		t.Fatal("expected missing PUBLIC_URL")
	}
}

func TestCheckTLSOffSkipsBadPair(t *testing.T) {
	dir := t.TempDir()
	ov := filepath.Join(dir, "config")
	body := "PUBLIC_URL=http://stash.test\nOIDC_GOOGLE_CLIENT_ID=cid\nLISTEN=127.0.0.1:8080\nTLS=0\nTLS_CERT=/no/cert\nTLS_KEY=/no/key\n"
	if err := os.WriteFile(ov, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Check("", ov, filepath.Join(dir, "nosecrets"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.UseTLS() {
		t.Fatal("expected tls off")
	}
}
