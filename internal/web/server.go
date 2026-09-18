// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

// Package web is the HTTP surface: auth, jail, listing, and upload.
package web

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/nyet/bootstash/internal/bind"
	"github.com/nyet/bootstash/internal/config"
	"github.com/nyet/bootstash/internal/oidcgoogle"
	"github.com/nyet/bootstash/internal/pamauth"
	"github.com/nyet/bootstash/internal/store"
)

const sessionTTL = 7 * 24 * time.Hour

// IDP is the OIDC authorization-code provider (Google in v1).
type IDP interface {
	AuthCodeURL(ctx context.Context, state, nonce, redirectURL string) (string, error)
	Exchange(ctx context.Context, code, nonce, redirectURL string) (*oidcgoogle.Identity, error)
}

// Server is the HTTP handler plus listener manager.
type Server struct {
	cfg     atomic.Value // *config.Config
	store   *store.Store
	idp     IDP
	pam     pamauth.Authenticator
	cert    atomic.Value // *tls.Certificate
	manager *bind.Manager
	key     []byte
}

// New constructs a server. cfg must already be Ready() for production start.
func New(cfg *config.Config, st *store.Store, idp IDP, pam pamauth.Authenticator, key []byte) (*Server, error) {
	if err := ensureLayout(cfg.Data); err != nil {
		return nil, err
	}
	s := &Server{store: st, idp: idp, pam: pam, key: key}
	s.cfg.Store(cfg)
	s.manager = bind.NewManager(s, cfg.UnixGroup, s.certificate)
	return s, nil
}

// Handler returns the HTTP handler (the server itself).
func (s *Server) Handler() http.Handler { return s }

func (s *Server) config() *config.Config {
	return s.cfg.Load().(*config.Config)
}

func (s *Server) certificate() (*tls.Certificate, error) {
	v := s.cert.Load()
	if v == nil {
		return nil, fmt.Errorf("no TLS certificate loaded")
	}
	c := v.(*tls.Certificate)
	return c, nil
}

// SetConfig replaces the runtime config (SIGHUP after a successful parse).
func (s *Server) SetConfig(cfg *config.Config) {
	s.cfg.Store(cfg)
}

// LoadCertificate reads cert and key from disk. On failure the previous cert is kept.
func (s *Server) LoadCertificate(certFile, keyFile string) error {
	c, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	s.cert.Store(&c)
	return nil
}

// SyncBinds applies cfg.Binds. CIDR empty-match errors are returned to the caller
// on first start; on reload they keep the previous listeners for that spec.
func (s *Server) SyncBinds(reload bool) error {
	cfg := s.config()
	var specs []bind.Spec
	for _, raw := range cfg.Binds {
		sp, err := bind.ParseSpec(raw)
		if err != nil {
			return fmt.Errorf("BIND %q: %w", raw, err)
		}
		specs = append(specs, *sp)
	}
	return s.manager.Sync(specs, cfg.TLSCert != "", reload)
}

// Close shuts down listeners.
func (s *Server) Close(ctx context.Context) error {
	if s.manager == nil {
		return nil
	}
	return s.manager.Close(ctx)
}

func ensureLayout(data string) error {
	if err := os.MkdirAll(filepath.Join(data, "shared"), 0750); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(data, "users"), 0750); err != nil {
		return err
	}
	return os.MkdirAll(filepath.Join(data, "state"), 0700)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r = s.applyForwarded(r)
	switch {
	case r.URL.Path == "/":
		s.handleRoot(w, r)
	case r.URL.Path == "/login":
		s.handleLogin(w, r)
	case r.URL.Path == "/oidc/callback":
		s.handleCallback(w, r)
	case r.URL.Path == "/link":
		s.handleLink(w, r)
	case r.URL.Path == "/unlink":
		s.handleUnlink(w, r)
	case strings.HasPrefix(r.URL.Path, "/files"):
		s.handleFiles(w, r, false)
	case strings.HasPrefix(r.URL.Path, "/home"):
		s.handleFiles(w, r, true)
	case strings.HasPrefix(r.URL.Path, "/static/"):
		s.handleStatic(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) applyForwarded(r *http.Request) *http.Request {
	if r.TLS != nil {
		return r
	}
	if p := r.Header.Get("X-Forwarded-Proto"); p != "" {
		r.URL.Scheme = p
	}
	if h := r.Header.Get("X-Forwarded-Host"); h != "" {
		r.Host = h
	}
	return r
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sess := s.session(r)
	if sess == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if sess.PAMUser == "" {
		http.Redirect(w, r, "/link", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/home/", http.StatusFound)
}

func (s *Server) session(r *http.Request) *store.Session {
	c, err := r.Cookie(s.cookieName())
	if err != nil || c.Value == "" {
		return nil
	}
	sess, err := s.store.GetSession(c.Value)
	if err != nil {
		return nil
	}
	return sess
}

func (s *Server) cookieName() string {
	if strings.HasPrefix(s.config().PublicURL, "https://") {
		return "__Host-bootstash"
	}
	return "bootstash"
}

func (s *Server) setSessionCookie(w http.ResponseWriter, sess *store.Session) {
	cfg := s.config()
	secure := strings.HasPrefix(cfg.PublicURL, "https://")
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName(),
		Value:    sess.ID,
		Path:     "/",
		Secure:   secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  sess.Expires,
	})
}

func (s *Server) redirectURI() string {
	return s.config().PublicURL + "/oidc/callback"
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (s *Server) signState(nonce string) (string, error) {
	ts := fmt.Sprintf("%d", time.Now().Unix())
	payload := ts + ":" + nonce
	mac := hmac.New(sha256.New, s.key)
	_, _ = mac.Write([]byte(payload))
	sum := mac.Sum(nil)
	raw := payload + ":" + hex.EncodeToString(sum)
	return base64.RawURLEncoding.EncodeToString([]byte(raw)), nil
}

func (s *Server) verifyState(state string) (string, error) {
	b, err := base64.RawURLEncoding.DecodeString(state)
	if err != nil {
		return "", err
	}
	parts := strings.Split(string(b), ":")
	if len(parts) != 3 {
		return "", fmt.Errorf("bad state")
	}
	payload := parts[0] + ":" + parts[1]
	mac := hmac.New(sha256.New, s.key)
	_, _ = mac.Write([]byte(payload))
	want, err := hex.DecodeString(parts[2])
	if err != nil {
		return "", err
	}
	if !hmac.Equal(mac.Sum(nil), want) {
		return "", fmt.Errorf("bad state mac")
	}
	sec, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return "", err
	}
	if time.Since(time.Unix(sec, 0)) > 15*time.Minute {
		return "", fmt.Errorf("state expired")
	}
	return parts[1], nil
}
