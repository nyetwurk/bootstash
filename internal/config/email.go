// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package config

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode"
)

// NormalizeEmail trims and lowercases an address. It does not fold
// Gmail dots or plus-tags. The operator types the address Google asserts.
func NormalizeEmail(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || len(s) > 254 {
		return "", fmt.Errorf("invalid address %q", s)
	}
	local, domain, ok := strings.Cut(s, "@")
	if !ok || local == "" || domain == "" || strings.Contains(domain, "@") {
		return "", fmt.Errorf("invalid address %q", s)
	}
	if strings.ContainsAny(s, " /\\") {
		return "", fmt.Errorf("invalid address %q", s)
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f || unicode.IsSpace(r) {
			return "", fmt.Errorf("invalid address %q", s)
		}
	}
	return s, nil
}

// EmailCubbyID is the lowercase hex SHA-256 of the normalized address.
// The address is not a path component. The same address always returns
// the same id.
func EmailCubbyID(email string) (string, error) {
	n, err := NormalizeEmail(email)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(n))
	return hex.EncodeToString(sum[:]), nil
}

// AllowsEmail reports whether email may sign in. An empty allowlist
// admits every address the provider asserts.
func (c *Config) AllowsEmail(email string) bool {
	if c == nil || len(c.AllowedEmails) == 0 {
		return true
	}
	n, err := NormalizeEmail(email)
	if err != nil {
		return false
	}
	for _, a := range c.AllowedEmails {
		if a == n {
			return true
		}
	}
	return false
}

func parseAllowedEmails(lines []string) ([]string, error) {
	var out []string
	seen := make(map[string]struct{})
	for _, line := range lines {
		for _, p := range strings.FieldsFunc(line, func(r rune) bool {
			return r == ',' || unicode.IsSpace(r)
		}) {
			if p == "" {
				continue
			}
			n, err := NormalizeEmail(p)
			if err != nil {
				return nil, fmt.Errorf("ALLOWED_EMAILS: %w", err)
			}
			if _, ok := seen[n]; ok {
				continue
			}
			seen[n] = struct{}{}
			out = append(out, n)
		}
	}
	return out, nil
}
