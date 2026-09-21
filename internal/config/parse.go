// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package config

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"unicode"
)

func parseFile(path string) (map[string][]string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string][]string{}, nil
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
		out[key] = append(out[key], unquote(strings.TrimSpace(val)))
	}
	return out, sc.Err()
}

func validKey(k string) bool {
	if k == "" || k[0] < 'A' || k[0] > 'Z' {
		return false
	}
	for i := 1; i < len(k); i++ {
		c := k[i]
		if (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}

func unquote(s string) string {
	if len(s) < 2 {
		return s
	}
	if s[0] == '"' && s[len(s)-1] == '"' {
		return strings.ReplaceAll(s[1:len(s)-1], `\"`, `"`)
	}
	if s[0] == '\'' && s[len(s)-1] == '\'' {
		return s[1 : len(s)-1]
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

func badName(s string) bool {
	return s == "." || s == ".." || strings.ContainsAny(s, "/\\:\x00")
}

func parseAdminUsers(s string) ([]string, error) {
	var out []string
	for _, p := range strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || unicode.IsSpace(r)
	}) {
		if p == "" {
			continue
		}
		if badName(p) {
			return nil, fmt.Errorf("ADMIN_USERS: invalid name %q", p)
		}
		out = append(out, p)
	}
	return out, nil
}

func parseBool(s string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true, nil
	case "0", "false", "no", "off":
		return false, nil
	default:
		return false, fmt.Errorf("want 0/1, false/true, no/yes, or off/on")
	}
}

// parseAutoOff: auto/maybe means enabled (disable false). yes/no and
// the other bool pairs follow parseBool (yes = enabled). Used by TLS
// and OVPN_TOKEN.
func parseAutoOff(s string) (disable bool, err error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "auto", "maybe":
		return false, nil
	}
	on, err := parseBool(s)
	if err != nil {
		return false, fmt.Errorf("want auto, maybe, yes/no, true/false, on/off, or 0/1")
	}
	return !on, nil
}

var sizeSuffix = []struct {
	suf  string
	mult int64
}{
	{"KIB", 1024},
	{"MIB", 1024 * 1024},
	{"GIB", 1024 * 1024 * 1024},
	{"KB", 1000},
	{"MB", 1000 * 1000},
	{"GB", 1000 * 1000 * 1000},
	{"K", 1024},
	{"M", 1024 * 1024},
	{"G", 1024 * 1024 * 1024},
}

func parseSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	upper := strings.ToUpper(s)
	mult := int64(1)
	for _, u := range sizeSuffix {
		if strings.HasSuffix(upper, u.suf) {
			mult = u.mult
			s = s[:len(s)-len(u.suf)]
			break
		}
	}
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
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
