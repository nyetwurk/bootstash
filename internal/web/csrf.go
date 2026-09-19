// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package web

import (
	"net/http"
	"strings"
)

func (s *Server) checkCSRF(r *http.Request) bool {
	want := s.config().PublicURL
	origin := strings.TrimRight(r.Header.Get("Origin"), "/")
	if origin != "" && origin != "null" {
		return origin == want
	}
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin":
		return true
	case "cross-site", "same-site":
		return false
	default:
		// "" or "none": some browsers omit Origin on same-origin form POST.
		ref := r.Header.Get("Referer")
		return strings.HasPrefix(ref, want+"/") || ref == want
	}
}

func (s *Server) requireCSRF(w http.ResponseWriter, r *http.Request) bool {
	if s.checkCSRF(r) {
		return true
	}
	s.replyError(w, r, http.StatusForbidden, "This request was rejected.")
	return false
}
