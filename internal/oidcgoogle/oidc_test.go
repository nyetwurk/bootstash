// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package oidcgoogle

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
)

const discoveryJSON = `{
  "issuer": "https://accounts.google.com",
  "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
  "token_endpoint": "https://oauth2.googleapis.com/token",
  "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
  "id_token_signing_alg_values_supported": ["RS256"]
}`

type discoveryRT struct{}

func (discoveryRT) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host == "accounts.google.com" && strings.HasSuffix(req.URL.Path, "/.well-known/openid-configuration") {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(discoveryJSON)),
			Request:    req,
		}, nil
	}
	return nil, fmt.Errorf("unexpected %s %s", req.Method, req.URL)
}

func testProvider(t *testing.T) (*Provider, url.Values) {
	t.Helper()
	ctx := oidc.ClientContext(t.Context(), &http.Client{Transport: discoveryRT{}})
	p := &Provider{ClientID: "cid", ClientSecret: "secret"}
	raw, _, err := p.AuthCodeURL(ctx, "st", "n", "https://stash.test/oidc/callback")
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return p, u.Query()
}

func TestAuthCodeURL(t *testing.T) {
	_, q := testProvider(t)
	if q.Get("client_id") != "cid" {
		t.Fatalf("client_id %q", q.Get("client_id"))
	}
	if q.Get("state") != "st" {
		t.Fatalf("state %q", q.Get("state"))
	}
	if q.Get("nonce") != "n" {
		t.Fatalf("nonce %q", q.Get("nonce"))
	}
	if q.Get("redirect_uri") != "https://stash.test/oidc/callback" {
		t.Fatalf("redirect_uri %q", q.Get("redirect_uri"))
	}
	if !strings.Contains(q.Get("scope"), "openid") {
		t.Fatalf("scope %q", q.Get("scope"))
	}
}

func TestAuthCodeURLPKCE(t *testing.T) {
	_, q := testProvider(t)
	if q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
		t.Fatalf("pkce challenge=%q method=%q", q.Get("code_challenge"), q.Get("code_challenge_method"))
	}
}
