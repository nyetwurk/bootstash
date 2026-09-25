// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package web

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/nyet/bootstash/internal/jail"
)

func TestFormatSize(t *testing.T) {
	cases := []struct {
		n    int64
		want string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1023, "1023 B"},
		{1024, "1 KiB"},
		{1536, "1.5 KiB"},
		{1048576, "1 MiB"},
		{1572864, "1.5 MiB"},
	}
	for _, c := range cases {
		if got := formatSize(c.n); got != c.want {
			t.Errorf("formatSize(%d)=%q want %q", c.n, got, c.want)
		}
	}
}

func TestFormatDateUTC(t *testing.T) {
	ts := time.Date(2026, 9, 17, 15, 4, 0, 0, time.UTC)
	if got := formatDate(ts); got != "2026-09-17 15:04" {
		t.Fatalf("formatDate=%q", got)
	}
}

func TestPickOvpn(t *testing.T) {
	if pickOvpn(nil) != "" {
		t.Fatal("empty")
	}
	if pickOvpn([]string{"a.ovpn"}) != "a.ovpn" {
		t.Fatal("one")
	}
	if pickOvpn([]string{"a.ovpn", "client.ovpn"}) != "client.ovpn" {
		t.Fatal("prefer client.ovpn")
	}
	if pickOvpn([]string{"kit/a.ovpn", "kit/b.ovpn"}) != "" {
		t.Fatal("several without client.ovpn")
	}
	if pickOvpn([]string{"kit/client.ovpn", "a.ovpn"}) != "kit/client.ovpn" {
		t.Fatal("one nested client.ovpn")
	}
	if pickOvpn([]string{"client.ovpn", "kit/client.ovpn"}) != "" {
		t.Fatal("several client.ovpn")
	}
}

func TestOvpnDisplayName(t *testing.T) {
	if ovpnDisplayName("nyet-tcp.ovpn", nil) != "nyet-tcp" {
		t.Fatal("no remote")
	}
	if ovpnDisplayName("kit/a.ovpn", nil) != "kit_a" {
		t.Fatal("nested")
	}
	if ovpnDisplayName("nyet-tcp.ovpn", []byte("client\nremote vpn.example 1194 udp\n")) != "vpn.example [nyet-tcp]" {
		t.Fatal("remote [file]")
	}
	if ovpnDisplayName("host.ovpn", []byte("remote host\n")) != "host" {
		t.Fatal("same as remote")
	}
	got := string(ovpnTitledProfile("nyet-tcp.ovpn", []byte("remote vpn.example\n")))
	if !strings.Contains(got, `setenv FRIENDLY_NAME "vpn.example [nyet-tcp]"`) || !strings.Contains(got, "remote vpn.example") {
		t.Fatalf("titled %q", got)
	}
	keep := []byte("# OVPN_ACCESS_SERVER_FRIENDLY_NAME=mine\nremote vpn.example\n")
	if string(ovpnTitledProfile("nyet-tcp.ovpn", keep)) != string(keep) {
		t.Fatal("leave existing title")
	}
}

func TestOvpnCleanLabel(t *testing.T) {
	cases := []struct {
		rel, body, want string
	}{
		{`a\b.ovpn`, "", `a_b`},
		{`say"hi.ovpn`, "", `say_hi`},
		{"a\nb.ovpn", "", "a_b"},
		{"a\rb.ovpn", "", "a_b"},
		{"a[b].ovpn", "", "a_b_"},
		{"a\tb.ovpn", "", "a_b"},
		{"café.ovpn", "", "caf_"},
		{"nyet.ovpn", "remote vpn.example\\evil\n", `vpn.example_evil [nyet]`},
		{"nyet.ovpn", "remote \"quoted\"\n", `_quoted_ [nyet]`},
		{"nyet.ovpn", "remote host\rname\n", `host [nyet]`},
		{"nyet.ovpn", "remote [vpn]\n", `_vpn_ [nyet]`},
		{"nyet.ovpn", "remote host\tname extra\n", `host [nyet]`},
		{"nyet.ovpn", "remote café.example\n", `caf_.example [nyet]`},
		{"a;b$(x)`y`.ovpn", "remote host;rm\n", `host_rm [a_b__x__y_]`},
	}
	for _, c := range cases {
		got := ovpnDisplayName(c.rel, []byte(c.body))
		if got != c.want {
			t.Errorf("display %q body %q = %q want %q", c.rel, c.body, got, c.want)
		}
		for _, r := range got {
			if r > 127 || r == '\\' || r == '"' || r == '\n' || r == '\r' || r == '\t' {
				t.Errorf("display %q has raw %q", got, r)
			}
		}
		out := string(ovpnTitledProfile(c.rel, []byte(c.body)))
		title := "# OVPN_ACCESS_SERVER_FRIENDLY_NAME=" + got + "\n# OVPN_ACCESS_SERVER_PROFILE=" + got + "\nsetenv FRIENDLY_NAME \"" + got + "\"\n"
		if !strings.HasPrefix(out, title) {
			t.Errorf("titled %q body %q:\n%s", c.rel, c.body, out)
		}
	}
}

func TestDownloadNameIn(t *testing.T) {
	cases := []struct {
		listing, file, want string
	}{
		{"", "a.txt", "a.txt"},
		{"kit", "kit/a.txt", "a.txt"},
		{"", "kit/a.txt", ""},
		{"kit", "a.txt", ""},
		{"kit", "kit/sub/a.txt", ""},
	}
	for _, c := range cases {
		if got := downloadNameIn(c.listing, c.file); got != c.want {
			t.Errorf("downloadNameIn(%q,%q)=%q want %q", c.listing, c.file, got, c.want)
		}
	}
}

func TestJailErrKey(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{jail.ErrEscape, "not-allowed"},
		{fmt.Errorf("%w: too many", jail.ErrEscape), "not-allowed"},
		{syscall.EACCES, "denied"},
		{os.ErrNotExist, "missing"},
		{jail.ErrNotDir, "not-a-folder"},
		{syscall.ENOTDIR, "not-a-folder"},
		{errors.New("io"), "failed"},
	}
	for _, c := range cases {
		if got := jailErrKey(c.err); got != c.want {
			t.Errorf("jailErrKey(%v)=%q want %q", c.err, got, c.want)
		}
	}
	if listingErrMessage("failed") != "Could not open that." {
		t.Fatalf("failed message %q", listingErrMessage("failed"))
	}
	if listingErrMessage("too-large") != "That file is too large." {
		t.Fatalf("too-large message %q", listingErrMessage("too-large"))
	}
}
