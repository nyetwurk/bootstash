// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type googleClientJSON struct {
	Web          *googleClientBlock `json:"web"`
	Installed    *googleClientBlock `json:"installed"`
	ClientID     string             `json:"client_id"`
	ClientSecret string             `json:"client_secret"`
}

type googleClientBlock struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// ParseGoogleClientJSON reads a Google Cloud OAuth client download.
// Prefers the "web" object (Web application).
func ParseGoogleClientJSON(b []byte) (clientID, clientSecret string, err error) {
	var doc googleClientJSON
	if err := json.Unmarshal(b, &doc); err != nil {
		return "", "", fmt.Errorf("Google client JSON: %w", err)
	}
	switch {
	case doc.Web != nil:
		clientID, clientSecret = doc.Web.ClientID, doc.Web.ClientSecret
	case doc.Installed != nil:
		return "", "", fmt.Errorf("Google client JSON is a Desktop client; download the Web application JSON")
	default:
		clientID, clientSecret = doc.ClientID, doc.ClientSecret
	}
	if strings.TrimSpace(clientID) == "" {
		return "", "", fmt.Errorf("Google client JSON: missing web.client_id")
	}
	return strings.TrimSpace(clientID), strings.TrimSpace(clientSecret), nil
}

func parseSecrets(path string) (map[string][]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string][]string{}, nil
		}
		return nil, err
	}
	trim := bytes.TrimSpace(b)
	if len(trim) == 0 {
		return map[string][]string{}, nil
	}
	if trim[0] != '{' {
		return parseReader(path, bytes.NewReader(b))
	}
	id, secret, err := ParseGoogleClientJSON(trim)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	out := map[string][]string{
		"OIDC_GOOGLE_CLIENT_ID": {id},
	}
	if secret != "" {
		out["OIDC_GOOGLE_CLIENT_SECRET"] = []string{secret}
	}
	return out, nil
}
