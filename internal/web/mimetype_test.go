// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package web

import (
	"strings"
	"testing"
	"testing/fstest"
)

func TestParseMimeTypes(t *testing.T) {
	in := `
# comment
text/plain txt text
application/pdf pdf
inode/directory
not-a-type txt
text/html txt
application/x-foo foo.bar gz/out
application/wasm wasm
`
	m, err := parseMimeTypes(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		".txt":  "text/plain",
		".text": "text/plain",
		".pdf":  "application/pdf",
		".wasm": "application/wasm",
	}
	if len(m) != len(want) {
		t.Fatalf("got %#v", m)
	}
	for k, v := range want {
		if m[k] != v {
			t.Errorf("%s=%q want %q", k, m[k], v)
		}
	}
}

func TestLoadMimeTypesLocalWins(t *testing.T) {
	fsys := fstest.MapFS{
		"mime.types": &fstest.MapFile{
			Data: []byte("text/plain txt\napplication/octet-stream ovpn\n"),
		},
		"mime-local.types": &fstest.MapFile{
			Data: []byte("application/x-openvpn-profile ovpn\n"),
		},
	}
	m, err := loadMimeTypes(fsys)
	if err != nil {
		t.Fatal(err)
	}
	if m[".txt"] != "text/plain" {
		t.Fatalf("txt %q", m[".txt"])
	}
	if m[".ovpn"] != ovpnProfileType {
		t.Fatalf("ovpn %q", m[".ovpn"])
	}
}

func TestFileContentType(t *testing.T) {
	cases := []struct {
		name, ctype, disp string
	}{
		{"note.txt", "text/plain; charset=utf-8", "attachment"},
		{"x.bin", "application/octet-stream", "attachment"},
		{"client.ovpn", ovpnProfileType, "inline"},
		{"CLIENT.OVPN", ovpnProfileType, "inline"},
		{"pic.png", "image/png", "inline"},
		{"pic.svg", "image/svg+xml", "inline"},
		{"doc.pdf", "application/pdf", "inline"},
		{"clip.mp4", "video/mp4", "inline"},
		{"song.mp3", "audio/mpeg", "inline"},
		{"app.wasm", "application/wasm", "attachment"},
		{"data.webp", "image/webp", "inline"},
		{"noext", "application/octet-stream", "attachment"},
		{"weird.unknownext", "application/octet-stream", "attachment"},
	}
	for _, c := range cases {
		got := fileContentType(c.name)
		if got != c.ctype {
			t.Errorf("fileContentType(%q)=%q want %q", c.name, got, c.ctype)
		}
		if d := contentDisposition(got); d != c.disp {
			t.Errorf("contentDisposition(%q)=%q want %q", got, d, c.disp)
		}
	}
}
