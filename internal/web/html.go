// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package web

import (
	"embed"
	"html/template"
	"io/fs"
	"net/http"
	"path"

	"github.com/nyet/bootstash/internal/store"
)

//go:embed templates/*
var templateFS embed.FS

var pages = template.Must(template.ParseFS(templateFS, "templates/*.html"))

type pageData struct {
	Title    string
	Error    string
	Hint     string
	Heading  string
	Parent   string
	Action   string
	CanWrite bool
	SignedIn bool
	PAMUser  string
	OIDCUser string
	Entries  []listEntry
}

type listEntry struct {
	Name string
	Href string
	Size string
	Date string
	Dir  bool
}

func (s *Server) render(w http.ResponseWriter, name string, data pageData) {
	if data.Title == "" {
		data.Title = "bootstash"
	}
	src := pages.Lookup(name)
	if src == nil {
		http.Error(w, "template", http.StatusInternalServerError)
		return
	}
	t, err := pages.Clone()
	if err != nil {
		http.Error(w, "template", http.StatusInternalServerError)
		return
	}
	if _, err := t.AddParseTree("body", src.Tree); err != nil {
		http.Error(w, "template", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, "layout", data); err != nil {
		http.Error(w, "template", http.StatusInternalServerError)
	}
}

func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := path.Base(r.URL.Path)
	if name != "style.css" {
		http.NotFound(w, r)
		return
	}
	b, err := fs.ReadFile(templateFS, "templates/style.css")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	_, _ = w.Write(b)
}

func sessionPage(sess *store.Session, data pageData) pageData {
	data.SignedIn = true
	if sess != nil {
		data.PAMUser = sess.PAMUser
		data.OIDCUser = sess.Email
		if data.OIDCUser == "" {
			data.OIDCUser = sess.Sub
		}
	}
	return data
}
