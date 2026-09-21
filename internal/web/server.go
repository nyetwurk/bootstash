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
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nyet/bootstash/internal/bind"
	"github.com/nyet/bootstash/internal/config"
	"github.com/nyet/bootstash/internal/oidcgoogle"
	"github.com/nyet/bootstash/internal/osutil"
	"github.com/nyet/bootstash/internal/pamauth"
	"github.com/nyet/bootstash/internal/store"
)

const sessionTTL = 7 * 24 * time.Hour
const oauthTTL = 15 * time.Minute
const oauthMaxTx = 1024

type oauthTx struct {
	nonce    string
	verifier string
	exp      time.Time
}

// IDP is the OIDC authorization-code provider (currently Google).
type IDP interface {
	AuthCodeURL(ctx context.Context, state, nonce, redirectURL string) (authURL, verifier string, err error)
	Exchange(ctx context.Context, code, nonce, redirectURL, verifier string) (*oidcgoogle.Identity, error)
}

// Server is the HTTP handler plus listener manager.
type Server struct {
	cfg         atomic.Value // *config.Config
	store       *store.Store
	idp         IDP
	pam         pamauth.Authenticator
	cert        atomic.Value // *tls.Certificate
	manager     *bind.Manager
	key         []byte
	oauthMu     sync.Mutex
	oauthTx     map[string]oauthTx
	ovpnMu      sync.Mutex
	ovpnTickets map[string]ovpnTicket
}

// ovpnTicketTTL is the Connect URL-import handoff envelope, not a
// privacy bound. The clock starts at mint (HTML render). Chrome's
// "Open OpenVPN Connect?" prompt, Connect's confirm, and a retry
// (HEAD then GET) must still find the ticket.
//
// Mint-on-tap cannot move the clock: Chrome drops the user-gesture
// if the tap fetches a ticket then navigates to openvpn:// (a 302
// onto the scheme is the same failure). A shorter TTL just 404s
// slow taps; the token stays a capability URL until it expires.
// Disable minting if that is unacceptable.
const ovpnTicketTTL = 60 * time.Second
const ovpnMaxTickets = 1024
const ovpnTicketUses = 2

type ovpnTicket struct {
	pam  string
	rel  string
	exp  time.Time
	left int
}

// New constructs a server. cfg must already be Ready() for production start.
func New(cfg *config.Config, st *store.Store, idp IDP, pam pamauth.Authenticator, key []byte) (*Server, error) {
	if err := ensureLayout(cfg.Data); err != nil {
		return nil, err
	}
	s := &Server{store: st, idp: idp, pam: pam, key: key}
	s.cfg.Store(cfg)
	s.manager = bind.NewManager(s, cfg.UnixGroup, s.certificate)
	s.fixCubbies()
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
	s.fixCubbies()
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
			return fmt.Errorf("LISTEN %q: %w", raw, err)
		}
		specs = append(specs, *sp)
	}
	return s.manager.Sync(specs, cfg.UseTLS(), reload)
}

// Close shuts down listeners.
func (s *Server) Close(ctx context.Context) error {
	if s.manager == nil {
		return nil
	}
	return s.manager.Close(ctx)
}

func ensureLayout(data string) error {
	users := filepath.Join(data, "users")
	if err := os.MkdirAll(users, 0711); err != nil {
		return err
	}
	// umask 007 would strip o+x from MkdirAll; the cubby owner must
	// be able to traverse users/ without listing it.
	if err := osutil.Chmod(users, 0711); err != nil {
		return err
	}
	return os.MkdirAll(filepath.Join(data, "state"), 0700)
}

func setSecurityHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "same-origin")
	h.Set("Content-Security-Policy", "frame-ancestors 'none'")
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	switch {
	case r.URL.Path == "/":
		s.handleRoot(w, r)
	case r.URL.Path == "/login":
		s.handleLogin(w, r)
	case r.URL.Path == "/oidc/callback":
		s.handleCallback(w, r)
	case r.URL.Path == "/link":
		s.handleLink(w, r)
	case r.URL.Path == "/logout":
		s.handleLogout(w, r)
	case strings.HasPrefix(r.URL.Path, "/home"):
		s.handleFiles(w, r)
	case r.URL.Path == "/openvpn-api/profile":
		s.handleOpenVPNProfile(w, r)
	case r.URL.Path == "/rest/GetUserlogin", r.URL.Path == "/rest/GetAutologin":
		s.handleOpenVPNRest(w, r)
	case strings.HasPrefix(r.URL.Path, "/static/"):
		s.handleStatic(w, r)
	default:
		s.replyError(w, r, http.StatusNotFound, "That page is not here.")
	}
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	http.Redirect(w, r, s.entryPath(r), http.StatusFound)
}

// ovpnWebAuth tells OpenVPN Connect to open a normal browser (Google
// OIDC) instead of Access Server REST or an in-app webview.
const ovpnWebAuth = "bootstash,external"

const ovpnRestXML = `<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Type>Authorization Required</Type>
  <Synopsis>REST method failed</Synopsis>
  <Message>%s</Message>
</Error>
`

func (s *Server) handleOpenVPNProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		log.Printf("openvpn %s %s from %s: method not allowed", r.Method, r.URL.Path, r.RemoteAddr)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if tok := r.URL.Query().Get("token"); tok != "" {
		s.serveOpenVPNTicket(w, r, tok)
		return
	}
	s.maybeOvpnWebAuth(w)
	sess := s.session(r)
	pam := "-"
	switch {
	case sess == nil:
	case sess.PAMUser == "":
		pam = "(unlinked)"
	default:
		pam = sess.PAMUser
	}
	if r.Method == http.MethodHead {
		auth := "Ovpn-WebAuth"
		if s.config().DisableOvpnToken {
			auth = "OVPN_TOKEN=no"
		}
		log.Printf("openvpn HEAD %s pam=%s from %s ua=%q: 200 %s", r.URL.RequestURI(), pam, r.RemoteAddr, r.UserAgent(), auth)
		w.WriteHeader(http.StatusOK)
		return
	}
	loc := s.entryPath(r)
	if loc == "/login" {
		log.Printf("openvpn GET %s pam=%s from %s ua=%q accept=%q: login", r.URL.RequestURI(), pam, r.RemoteAddr, r.UserAgent(), r.Header.Get("Accept"))
		s.setOvpnImport(w)
		s.render(w, "login", pageData{Title: "Sign in"})
		return
	}
	if loc == "/link" {
		log.Printf("openvpn GET %s pam=%s from %s ua=%q: redirect /link", r.URL.RequestURI(), pam, r.RemoteAddr, r.UserAgent())
		s.setOvpnImport(w)
		http.Redirect(w, r, loc, http.StatusFound)
		return
	}
	s.clearOvpnImport(w)
	s.serveOpenVPNProfile(w, r)
}

func (s *Server) handleOpenVPNRest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		log.Printf("openvpn rest %s %s from %s: method not allowed", r.Method, r.URL.Path, r.RemoteAddr)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	off := s.config().DisableOvpnToken
	auth := "Ovpn-WebAuth"
	msg := "Ovpn-WebAuth: " + ovpnWebAuth
	if off {
		auth = "OVPN_TOKEN=no"
		msg = "Authorization Required"
	}
	log.Printf("openvpn rest %s %s from %s ua=%q: 401 %s", r.Method, r.URL.RequestURI(), r.RemoteAddr, r.UserAgent(), auth)
	s.maybeOvpnWebAuth(w)
	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = fmt.Fprintf(w, ovpnRestXML, msg)
}

func (s *Server) maybeOvpnWebAuth(w http.ResponseWriter) {
	if s.config().DisableOvpnToken {
		return
	}
	w.Header().Set("Ovpn-WebAuth", ovpnWebAuth)
}

func (s *Server) entryPath(r *http.Request) string {
	sess := s.session(r)
	if sess == nil {
		return "/login"
	}
	if sess.PAMUser == "" {
		return "/link"
	}
	return "/home/"
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
	return s.hostCookie("__Host-bootstash", "bootstash")
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

func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	s.setCookie(w, s.cookieName(), "", -1)
}

func (s *Server) ovpnImportCookieName() string {
	return s.hostCookie("__Host-bootstash-ovpn", "bootstash_ovpn")
}

func (s *Server) setOvpnImport(w http.ResponseWriter) {
	s.setCookie(w, s.ovpnImportCookieName(), "1", int((15 * time.Minute).Seconds()))
}

func (s *Server) clearOvpnImport(w http.ResponseWriter) {
	s.setCookie(w, s.ovpnImportCookieName(), "", -1)
}

func (s *Server) afterLogin(r *http.Request, linked bool) string {
	c, err := r.Cookie(s.ovpnImportCookieName())
	want := err == nil && c.Value == "1"
	dest := "/home/"
	if !linked {
		dest = "/link"
	} else if want {
		dest = "/openvpn-api/profile"
	}
	log.Printf("openvpn after-login linked=%v import-cookie=%v -> %s from %s", linked, want, dest, r.RemoteAddr)
	return dest
}

func (s *Server) noticeCookieName() string {
	return s.hostCookie("__Host-bootstash-notice", "bootstash_notice")
}

func (s *Server) setNotice(w http.ResponseWriter, key string) {
	if listingErrMessage(key) == "" {
		return
	}
	s.setCookie(w, s.noticeCookieName(), key, 60)
}

func (s *Server) takeNotice(w http.ResponseWriter, r *http.Request) string {
	c, err := r.Cookie(s.noticeCookieName())
	if err != nil || c.Value == "" {
		return ""
	}
	s.setCookie(w, s.noticeCookieName(), "", -1)
	return listingErrMessage(c.Value)
}

func (s *Server) downloadCookieName() string {
	return s.hostCookie("__Host-bootstash-dl", "bootstash_dl")
}

func (s *Server) setDownloadMark(w http.ResponseWriter, rel string) {
	rel = strings.Trim(path.Clean("/"+rel), "/")
	if rel == "" || rel == "." {
		return
	}
	s.setCookie(w, s.downloadCookieName(), url.QueryEscape(rel), 60)
}

func (s *Server) takeDownloadMark(w http.ResponseWriter, r *http.Request, listingRel string) string {
	c, err := r.Cookie(s.downloadCookieName())
	if err != nil || c.Value == "" {
		return ""
	}
	rel, err := url.QueryUnescape(c.Value)
	if err != nil {
		s.setCookie(w, s.downloadCookieName(), "", -1)
		return ""
	}
	name := downloadNameIn(listingRel, rel)
	if name == "" {
		return ""
	}
	s.setCookie(w, s.downloadCookieName(), "", -1)
	return name
}

func (s *Server) setCookie(w http.ResponseWriter, name, value string, maxAge int) {
	secure := strings.HasPrefix(s.config().PublicURL, "https://")
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Secure:   secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	})
}

func (s *Server) oauthCookieName() string {
	return s.hostCookie("__Host-bootstash-oauth", "bootstash_oauth")
}

func (s *Server) hostCookie(httpsName, httpName string) string {
	if strings.HasPrefix(s.config().PublicURL, "https://") {
		return httpsName
	}
	return httpName
}

func (s *Server) putOvpnTicket(pam, rel string) (string, error) {
	id, err := randomHex(16)
	if err != nil {
		return "", err
	}
	s.ovpnMu.Lock()
	defer s.ovpnMu.Unlock()
	if s.ovpnTickets == nil {
		s.ovpnTickets = make(map[string]ovpnTicket)
	}
	now := time.Now()
	for k, t := range s.ovpnTickets {
		if now.After(t.exp) {
			delete(s.ovpnTickets, k)
		}
	}
	if _, ok := s.ovpnTickets[id]; !ok && len(s.ovpnTickets) >= ovpnMaxTickets {
		return "", fmt.Errorf("ovpn tickets full")
	}
	s.ovpnTickets[id] = ovpnTicket{pam: pam, rel: rel, exp: now.Add(ovpnTicketTTL), left: ovpnTicketUses}
	return id, nil
}

func (s *Server) peekOvpnTicket(id string) (ovpnTicket, bool) {
	return s.lookupOvpnTicket(id, false)
}

func (s *Server) takeOvpnTicket(id string) (ovpnTicket, bool) {
	return s.lookupOvpnTicket(id, true)
}

func (s *Server) lookupOvpnTicket(id string, consume bool) (ovpnTicket, bool) {
	s.ovpnMu.Lock()
	defer s.ovpnMu.Unlock()
	t, ok := s.ovpnTickets[id]
	if !ok {
		return ovpnTicket{}, false
	}
	if time.Now().After(t.exp) {
		delete(s.ovpnTickets, id)
		return ovpnTicket{}, false
	}
	if !consume {
		return t, true
	}
	t.left--
	if t.left <= 0 {
		delete(s.ovpnTickets, id)
	} else {
		s.ovpnTickets[id] = t
	}
	return t, true
}

func (s *Server) putOauthTx(id, nonce, verifier string, exp time.Time) error {
	s.oauthMu.Lock()
	defer s.oauthMu.Unlock()
	if s.oauthTx == nil {
		s.oauthTx = make(map[string]oauthTx)
	}
	now := time.Now()
	for k, tx := range s.oauthTx {
		if now.After(tx.exp) {
			delete(s.oauthTx, k)
		}
	}
	if _, ok := s.oauthTx[id]; !ok && len(s.oauthTx) >= oauthMaxTx {
		return fmt.Errorf("oauth tx full")
	}
	s.oauthTx[id] = oauthTx{nonce: nonce, verifier: verifier, exp: exp}
	return nil
}

func (s *Server) takeOauthTx(id string) (nonce, verifier string, err error) {
	s.oauthMu.Lock()
	defer s.oauthMu.Unlock()
	tx, ok := s.oauthTx[id]
	if !ok {
		return "", "", fmt.Errorf("no oauth tx")
	}
	delete(s.oauthTx, id)
	if time.Now().After(tx.exp) {
		return "", "", fmt.Errorf("oauth tx expired")
	}
	return tx.nonce, tx.verifier, nil
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
