// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

// Package oidcgoogle implements Sign in with Google.
package oidcgoogle

import (
	"context"
	"fmt"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	// Issuer is Google's OpenID issuer.
	Issuer = "https://accounts.google.com"
)

// Identity is an OIDC (issuer, sub) plus display fields.
type Identity struct {
	Issuer  string
	Subject string
	Email   string
	Name    string
}

// Provider performs the Google authorization-code flow.
type Provider struct {
	ClientID     string
	ClientSecret string

	mu       sync.Mutex
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
}

func (p *Provider) get(ctx context.Context) (*oidc.Provider, *oidc.IDTokenVerifier, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.provider != nil {
		return p.provider, p.verifier, nil
	}
	prov, err := oidc.NewProvider(ctx, Issuer)
	if err != nil {
		return nil, nil, err
	}
	p.provider = prov
	p.verifier = prov.Verifier(&oidc.Config{ClientID: p.ClientID})
	return p.provider, p.verifier, nil
}

func (p *Provider) oauth(ctx context.Context, redirectURL string) (*oauth2.Config, error) {
	prov, _, err := p.get(ctx)
	if err != nil {
		return nil, err
	}
	return &oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     prov.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
	}, nil
}

// AuthCodeURL returns the Google authorization URL and a PKCE verifier.
func (p *Provider) AuthCodeURL(ctx context.Context, state, nonce, redirectURL string) (string, string, error) {
	cfg, err := p.oauth(ctx, redirectURL)
	if err != nil {
		return "", "", err
	}
	verifier := oauth2.GenerateVerifier()
	u := cfg.AuthCodeURL(state,
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.AccessTypeOnline,
		oauth2.S256ChallengeOption(verifier),
	)
	return u, verifier, nil
}

// Exchange trades a code for a verified identity.
func (p *Provider) Exchange(ctx context.Context, code, nonce, redirectURL, verifier string) (*Identity, error) {
	cfg, err := p.oauth(ctx, redirectURL)
	if err != nil {
		return nil, err
	}
	_, idtVerifier, err := p.get(ctx)
	if err != nil {
		return nil, err
	}
	var opts []oauth2.AuthCodeOption
	if verifier != "" {
		opts = append(opts, oauth2.VerifierOption(verifier))
	}
	tok, err := cfg.Exchange(ctx, code, opts...)
	if err != nil {
		return nil, err
	}
	raw, ok := tok.Extra("id_token").(string)
	if !ok || raw == "" {
		return nil, fmt.Errorf("no id_token")
	}
	idt, err := idtVerifier.Verify(ctx, raw)
	if err != nil {
		return nil, err
	}
	if idt.Nonce != nonce && nonce != "" {
		return nil, fmt.Errorf("nonce mismatch")
	}
	var claims struct {
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	_ = idt.Claims(&claims)
	iss := idt.Issuer
	if iss == "" {
		iss = Issuer
	}
	return &Identity{
		Issuer:  iss,
		Subject: idt.Subject,
		Email:   claims.Email,
		Name:    claims.Name,
	}, nil
}
