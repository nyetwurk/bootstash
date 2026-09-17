// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package web

import (
	"net/http"
	"strings"
)

func (s *Server) checkCSRF(r *http.Request) bool {
	cfg := s.config()
	origin := strings.TrimRight(r.Header.Get("Origin"), "/")
	if origin != "" {
		return origin == cfg.PublicOrigin
	}
	site := r.Header.Get("Sec-Fetch-Site")
	switch site {
	case "same-origin":
		return true
	case "none":
		// User-initiated same-origin navigations may send none; still require
		// the public origin as Referer when Origin is missing.
		ref := r.Header.Get("Referer")
		return strings.HasPrefix(ref, cfg.PublicOrigin+"/") || ref == cfg.PublicOrigin
	default:
		return false
	}
}

func (s *Server) requireCSRF(w http.ResponseWriter, r *http.Request) bool {
	if s.checkCSRF(r) {
		return true
	}
	http.Error(w, "csrf rejected", http.StatusForbidden)
	return false
}
