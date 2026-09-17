// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package web

import (
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/nyet/bootstash/internal/pamauth"
)

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.Query().Get("provider") == "" {
		s.render(w, "login", pageData{Title: "Sign in"})
		return
	}
	if r.URL.Query().Get("provider") != "google" {
		http.Error(w, "unknown provider", http.StatusNotFound)
		return
	}
	nonce, err := randomHex(16)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	state, err := s.signState(nonce)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	u, err := s.idp.AuthCodeURL(r.Context(), state, nonce, s.redirectURI())
	if err != nil {
		log.Printf("oidc auth url: %v", err)
		http.Error(w, "identity provider unavailable", http.StatusBadGateway)
		return
	}
	http.Redirect(w, r, u, http.StatusFound)
}

func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if errMsg := r.URL.Query().Get("error"); errMsg != "" {
		http.Error(w, "oidc error: "+errMsg, http.StatusBadRequest)
		return
	}
	nonce, err := s.verifyState(r.URL.Query().Get("state"))
	if err != nil {
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}
	id, err := s.idp.Exchange(r.Context(), r.URL.Query().Get("code"), nonce, s.redirectURI())
	if err != nil {
		log.Printf("oidc exchange: %v", err)
		http.Error(w, "login failed", http.StatusBadRequest)
		return
	}
	sess, err := s.store.CreateSession(id.Issuer, id.Subject, id.Email, sessionTTL)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.setSessionCookie(w, sess)
	if sess.PAMUser == "" {
		http.Redirect(w, r, "/link", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/home/", http.StatusFound)
}

func (s *Server) handleLink(w http.ResponseWriter, r *http.Request) {
	sess := s.session(r)
	if sess == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.render(w, "link", pageData{Title: "Link account", Hint: hintUsername(sess.Email)})
	case http.MethodPost:
		if !s.requireCSRF(w, r) {
			return
		}
		_ = r.ParseForm()
		user := strings.TrimSpace(r.FormValue("username"))
		pass := r.FormValue("password")
		if s.pam == nil {
			http.Error(w, "pam unavailable", http.StatusInternalServerError)
			return
		}
		if err := s.pam.Authenticate(user, pass); err != nil {
			s.render(w, "link", pageData{Title: "Link account", Error: "username or password not accepted", Hint: user})
			return
		}
		if _, err := pamauth.Lookup(user); err != nil {
			s.render(w, "link", pageData{Title: "Link account", Error: "unknown local user", Hint: user})
			return
		}
		if err := s.store.SetLink(sess.Iss, sess.Sub, user); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if err := s.ensureUserDir(user); err != nil {
			log.Printf("user dir: %v", err)
		}
		sess.PAMUser = user
		if err := s.store.SaveSession(sess); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/home/", http.StatusFound)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleUnlink(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireCSRF(w, r) {
		return
	}
	sess := s.session(r)
	if sess == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	_ = s.store.DeleteLink(sess.Iss, sess.Sub)
	sess.PAMUser = ""
	_ = s.store.SaveSession(sess)
	http.Redirect(w, r, "/link", http.StatusFound)
}

func (s *Server) ensureUserDir(pamUser string) error {
	dir := filepath.Join(s.config().Data, "users", pamUser)
	if err := os.MkdirAll(dir, 0770); err != nil {
		return err
	}
	if err := os.Chmod(dir, os.FileMode(02770)); err != nil {
		return err
	}
	acct, err := pamauth.Lookup(pamUser)
	if err != nil {
		return nil
	}
	gid := acct.GID
	if g, err := pamauth.LookupGroupGID(s.config().UnixGroup); err == nil {
		gid = g
	}
	if err := os.Chown(dir, acct.UID, gid); err != nil {
		log.Printf("chown %s: %v", dir, err)
	}
	return nil
}

func hintUsername(email string) string {
	if i := strings.IndexByte(email, '@'); i > 0 {
		return email[:i]
	}
	return ""
}
