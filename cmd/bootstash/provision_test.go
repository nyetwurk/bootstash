// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrintGoogleSetupRecommendations(t *testing.T) {
	var buf bytes.Buffer
	printGoogleSetup(&buf, googleSetup{
		Pub:      "https://stash.example",
		Redirect: "https://stash.example/oidc/callback",
		Proj:     "bootstash-home",
		TLS:      true,
		CertName: "stash.example",
		Binds:    []string{"127.0.0.1:8080"},
	})
	got := buf.String()
	want := []string{
		"1. GCP project",
		"Recommend: display name bootstash",
		"Current gcloud project: bootstash-home",
		"2. Branding / consent screen",
		"Recommend: External. Testing. App name bootstash",
		"3. OAuth client",
		"Recommend: type Web application",
		"https://stash.example/oidc/callback",
		"HTTPS: PEMs found",
		"does not change LISTEN",
		"CERT_NAME=stash.example",
		"4. Download the client JSON",
		"Not your Google account",
	}
	for _, s := range want {
		if !strings.Contains(got, s) {
			t.Fatalf("missing %q in:\n%s", s, got)
		}
	}
}

func TestPrintGoogleSetupHTTPWhenNoCerts(t *testing.T) {
	var buf bytes.Buffer
	printGoogleSetup(&buf, googleSetup{
		Pub:      "http://box.example:8080",
		Redirect: "http://box.example:8080/oidc/callback",
		Binds:    []string{"127.0.0.1:8080"},
	})
	got := buf.String()
	if !strings.Contains(got, "HTTP: no PEMs") || !strings.Contains(got, "letsencrypt-deploy sync") {
		t.Fatalf("%s", got)
	}
	if strings.Contains(got, "HTTPS: PEMs found") {
		t.Fatalf("tls advice on http origin:\n%s", got)
	}
}

func TestPrintGoogleSetupHTTPWhenTLSOff(t *testing.T) {
	var buf bytes.Buffer
	printGoogleSetup(&buf, googleSetup{
		Pub:      "https://stash.example",
		Redirect: "https://stash.example/oidc/callback",
		TLSOff:   true,
		Binds:    []string{"127.0.0.1:8080"},
	})
	got := buf.String()
	if !strings.Contains(got, "HTTP: TLS=no") || !strings.Contains(got, "not copy live/") {
		t.Fatalf("%s", got)
	}
	if strings.Contains(got, "HTTPS: PEMs found") {
		t.Fatalf("tls on:\n%s", got)
	}
}

func TestInstallGoogleClientJSONCopiesDownload(t *testing.T) {
	dir := t.TempDir()
	op := filepath.Join(dir, "config")
	src := filepath.Join(dir, "client_secret.json")
	sec := filepath.Join(dir, "oidc-google")
	body := `{"web":{"client_id":"cid.apps.googleusercontent.com","client_secret":"sekrit","project_id":"bootstash"}}` + "\n"
	if err := os.WriteFile(op, []byte("PUBLIC_URL=https://stash.test\nLISTEN=lo:8080\n"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	if err := installGoogleClientJSON(src, sec, ""); err != nil {
		t.Fatal(err)
	}
	opBody, err := os.ReadFile(op)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(opBody), "OIDC_GOOGLE") || strings.Contains(string(opBody), "client_id") {
		t.Fatalf("operator config mutated: %s", opBody)
	}
	got, err := os.ReadFile(sec)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != body {
		t.Fatalf("secrets %s", got)
	}
	st, err := os.Stat(sec)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0640 {
		t.Fatalf("mode %o", st.Mode().Perm())
	}
}

func TestInstallGoogleClientJSONRejectsDesktop(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "desktop.json")
	if err := os.WriteFile(src, []byte(`{"installed":{"client_id":"x","client_secret":"y"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := installGoogleClientJSON(src, filepath.Join(dir, "out"), ""); err == nil {
		t.Fatal("expected desktop JSON to fail")
	}
}
