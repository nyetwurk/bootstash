// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package web

import (
	"bufio"
	"embed"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"path"
	"strings"
)

const ovpnProfileType = "application/x-openvpn-profile"

//go:embed mime.types mime-local.types
var mimeTypeFiles embed.FS

var mimeByExt = mustLoadMimeTypes()

func mustLoadMimeTypes() map[string]string {
	m, err := loadMimeTypes(mimeTypeFiles)
	if err != nil {
		panic(err)
	}
	return m
}

func loadMimeTypes(fsys fs.FS) (map[string]string, error) {
	m, err := parseMimeTypesFile(fsys, "mime.types")
	if err != nil {
		return nil, err
	}
	extra, err := parseMimeTypesFile(fsys, "mime-local.types")
	if err != nil {
		return nil, err
	}
	for ext, typ := range extra {
		m[ext] = typ
	}
	return m, nil
}

func parseMimeTypesFile(fsys fs.FS, name string) (map[string]string, error) {
	f, err := fsys.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	m, err := parseMimeTypes(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return m, nil
}

// parseMimeTypes reads the Apache / Debian media-types format:
// `type ext [ext...]`. Comments and types with no extensions are skipped.
// The first mapping for an extension wins.
func parseMimeTypes(r io.Reader) (map[string]string, error) {
	out := make(map[string]string)
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		typ := fields[0]
		if !strings.Contains(typ, "/") {
			continue
		}
		for _, ext := range fields[1:] {
			ext = strings.ToLower(ext)
			if ext == "" || strings.ContainsAny(ext, "./") {
				continue
			}
			key := "." + ext
			if _, ok := out[key]; ok {
				continue
			}
			out[key] = typ
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func fileContentType(name string) string {
	ext := strings.ToLower(path.Ext(name))
	ctype := mimeByExt[ext]
	if ctype == "" {
		return "application/octet-stream"
	}
	if strings.HasPrefix(ctype, "text/") && !strings.Contains(ctype, "charset=") {
		return ctype + "; charset=utf-8"
	}
	return ctype
}

func contentDisposition(ctype string) string {
	media, _, err := mime.ParseMediaType(ctype)
	if err != nil {
		media = ctype
	}
	if strings.HasPrefix(media, "video/") || strings.HasPrefix(media, "audio/") ||
		strings.HasPrefix(media, "image/") || media == "application/pdf" ||
		media == ovpnProfileType {
		return "inline"
	}
	return "attachment"
}
