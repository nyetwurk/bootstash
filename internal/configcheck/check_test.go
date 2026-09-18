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

func TestCheckReadyAndBinds(t *testing.T) {
	dir := t.TempDir()
	ov := filepath.Join(dir, "config")
	body := "PUBLIC_ORIGIN=https://stash.test\nOIDC_GOOGLE_CLIENT_ID=cid\nBIND=127.0.0.1:8080\n"
	if err := os.WriteFile(ov, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Check("", ov, filepath.Join(dir, "nosecrets"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PublicOrigin != "https://stash.test" {
		t.Fatalf("%+v", cfg)
	}
}

func TestSummaryIncludesAdmins(t *testing.T) {
	cfg := &config.Config{PublicOrigin: "https://stash.test", Binds: []string{"127.0.0.1:8080"}, AdminUsers: []string{"alice"}}
	got := Summary(cfg)
	if !strings.Contains(got, "admins=alice") {
		t.Fatalf("%s", got)
	}
}

func TestCheckBadBind(t *testing.T) {
	dir := t.TempDir()
	ov := filepath.Join(dir, "config")
	body := "PUBLIC_ORIGIN=https://stash.test\nOIDC_GOOGLE_CLIENT_ID=cid\nBIND=127.0.0.1:0\n"
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
	// Unix-only BIND has no TCP port, so hostname -f cannot fill PUBLIC_ORIGIN.
	if err := os.WriteFile(ov, []byte("OIDC_GOOGLE_CLIENT_ID=cid\nBIND=unix:///tmp/bootstash.sock\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Check("", ov, filepath.Join(dir, "nosecrets")); err == nil {
		t.Fatal("expected missing PUBLIC_ORIGIN")
	}
}
