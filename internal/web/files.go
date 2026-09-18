// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package web

import (
	"io"
	"log"
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nyet/bootstash/internal/jail"
	"github.com/nyet/bootstash/internal/pamauth"
	"github.com/nyet/bootstash/internal/store"
)

func (s *Server) handleFiles(w http.ResponseWriter, r *http.Request) {
	sess := s.session(r)
	if sess == nil || sess.PAMUser == "" {
		http.Error(w, "login required", http.StatusUnauthorized)
		return
	}
	const prefix = "/home"
	if r.URL.Path == prefix {
		http.Redirect(w, r, prefix+"/", http.StatusFound)
		return
	}
	rel := strings.TrimPrefix(r.URL.Path, prefix+"/")
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		s.prepareCubbyRead(sess.PAMUser, rel)
	}
	rootPath, err := s.jailPath(sess)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	root, err := jail.OpenRoot(rootPath)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	defer root.Close()

	switch r.Method {
	case http.MethodGet, http.MethodHead:
		s.serveGet(w, r, root, prefix, rel)
	case http.MethodPut:
		if !s.requireWrite(w, r) {
			return
		}
		s.servePut(w, r, root, rel, sess)
	case http.MethodPost:
		if !s.requireWrite(w, r) {
			return
		}
		s.servePost(w, r, root, prefix, rel, sess)
	case http.MethodDelete:
		if !s.requireWrite(w, r) {
			return
		}
		s.serveDelete(w, r, root, rel, "")
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) requireWrite(w http.ResponseWriter, r *http.Request) bool {
	return s.requireCSRF(w, r)
}

// isAdmin is the v1 seam: ADMIN_USERS in operator config, linked PAM name, live config.
// It grants no extra HTTP powers.
func (s *Server) isAdmin(sess *store.Session) bool {
	if sess == nil || sess.PAMUser == "" {
		return false
	}
	return s.config().IsAdmin(sess.PAMUser)
}

func (s *Server) jailPath(sess *store.Session) (string, error) {
	if !pamauth.ValidUsername(sess.PAMUser) || !filepath.IsLocal(sess.PAMUser) {
		return "", os.ErrNotExist
	}
	return path.Join(s.config().Data, "users", sess.PAMUser), nil
}

func (s *Server) serveGet(w http.ResponseWriter, r *http.Request, root *jail.Root, prefix, rel string) {
	info, err := root.Stat(rel)
	if err != nil {
		if jail.IsNotExist(err) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if info.IsDir() {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		s.serveListing(w, r, root, prefix, rel)
		return
	}
	f, err := root.Open(rel)
	if err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	defer f.Close()
	ctype := mime.TypeByExtension(path.Ext(info.Name()))
	if ctype == "" {
		ctype = "application/octet-stream"
	}
	disp := "attachment"
	if strings.HasPrefix(ctype, "video/") || strings.HasPrefix(ctype, "audio/") ||
		strings.HasPrefix(ctype, "image/") || ctype == "application/pdf" {
		disp = "inline"
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Disposition", disp+"; filename=\""+info.Name()+"\"")
	http.ServeContent(w, r, info.Name(), info.ModTime(), f)
}

func (s *Server) serveListing(w http.ResponseWriter, r *http.Request, root *jail.Root, prefix, rel string) {
	infos, err := root.ReadDirNames(rel)
	if err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	sort.Slice(infos, func(i, j int) bool {
		return infos[i].Name() < infos[j].Name()
	})
	base := strings.TrimSuffix(prefix+"/"+rel, "/")
	if rel == "" {
		base = prefix
	}
	var entries []listEntry
	for _, fi := range infos {
		name := fi.Name()
		href := path.Join(base, name)
		if fi.IsDir() {
			href += "/"
		}
		entries = append(entries, listEntry{
			Name: name,
			Href: href,
			Size: strconv.FormatInt(fi.Size(), 10),
			Date: fi.ModTime().UTC().Format(time.RFC3339),
			Dir:  fi.IsDir(),
		})
	}
	parent := ""
	if rel != "" {
		parent = path.Dir(base)
		if parent == "." || parent == prefix {
			parent = prefix + "/"
		} else if !strings.HasSuffix(parent, "/") {
			parent += "/"
		}
	}
	heading := ""
	if rel != "" {
		heading = rel
	}
	s.render(w, "listing", sessionPage(s.session(r), pageData{
		Title:    heading,
		Heading:  heading,
		Parent:   parent,
		Action:   listingURL(prefix, rel),
		CanWrite: true,
		Entries:  entries,
	}))
}

func (s *Server) servePut(w http.ResponseWriter, r *http.Request, root *jail.Root, rel string, sess *store.Session) {
	if rel == "" || strings.HasSuffix(r.URL.Path, "/") {
		http.Error(w, "path required", http.StatusBadRequest)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, s.config().MaxUpload)
	f, err := root.Create(rel, 0660)
	if err != nil {
		statusFromJail(w, err)
		return
	}
	defer f.Close()
	if _, err := io.Copy(f, r.Body); err != nil {
		http.Error(w, "upload failed", http.StatusRequestEntityTooLarge)
		return
	}
	s.chownRel(root, rel, sess.PAMUser)
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) servePost(w http.ResponseWriter, r *http.Request, root *jail.Root, prefix, rel string, sess *store.Session) {
	ct := r.Header.Get("Content-Type")
	mkdir := r.URL.Query().Get("mkdir") != ""
	if strings.HasPrefix(ct, "multipart/form-data") {
		r.Body = http.MaxBytesReader(w, r.Body, s.config().MaxUpload+4096)
		if err := r.ParseMultipartForm(s.config().MaxUpload); err != nil {
			http.Error(w, "upload too large", http.StatusRequestEntityTooLarge)
			return
		}
		if r.FormValue("mkdir") != "" {
			mkdir = true
		}
		if r.FormValue("delete") != "" {
			s.doDeleteForm(w, r, root, prefix, rel, r.FormValue("name"))
			return
		}
		if mkdir {
			name := r.FormValue("name")
			s.doMkdir(w, r, root, prefix, rel, name, sess)
			return
		}
		fh, hdr, err := r.FormFile("file")
		if err != nil {
			http.Error(w, "file required", http.StatusBadRequest)
			return
		}
		defer fh.Close()
		name := hdr.Filename
		if n := r.FormValue("name"); n != "" {
			name = n
		}
		var ok bool
		name, ok = entryName(name)
		if !ok {
			http.Error(w, "invalid name", http.StatusBadRequest)
			return
		}
		dest := path.Join(rel, name)
		f, err := root.Create(dest, 0660)
		if err != nil {
			statusFromJail(w, err)
			return
		}
		defer f.Close()
		if _, err := io.Copy(f, fh); err != nil {
			http.Error(w, "upload failed", http.StatusRequestEntityTooLarge)
			return
		}
		s.chownRel(root, dest, sess.PAMUser)
		http.Redirect(w, r, listingURL(prefix, rel), http.StatusSeeOther)
		return
	}
	_ = r.ParseForm()
	if r.FormValue("delete") != "" {
		name := r.FormValue("name")
		s.doDeleteForm(w, r, root, prefix, rel, name)
		return
	}
	if mkdir || r.FormValue("mkdir") != "" {
		name := r.FormValue("name")
		s.doMkdir(w, r, root, prefix, rel, name, sess)
		return
	}
	http.Error(w, "bad request", http.StatusBadRequest)
}

func (s *Server) doMkdir(w http.ResponseWriter, r *http.Request, root *jail.Root, prefix, rel, name string, sess *store.Session) {
	if name == "" {
		name = path.Base(strings.TrimSuffix(rel, "/"))
		if rel == "" || name == "." || name == "/" {
			http.Error(w, "name required", http.StatusBadRequest)
			return
		}
		if err := root.Mkdir(rel, 0770); err != nil {
			statusFromJail(w, err)
			return
		}
		s.chownRel(root, rel, sess.PAMUser)
		w.WriteHeader(http.StatusCreated)
		return
	}
	name, ok := entryName(name)
	if !ok {
		http.Error(w, "invalid name", http.StatusBadRequest)
		return
	}
	dest := path.Join(rel, name)
	if err := root.Mkdir(dest, 0770); err != nil {
		statusFromJail(w, err)
		return
	}
	s.chownRel(root, dest, sess.PAMUser)
	http.Redirect(w, r, listingURL(prefix, rel), http.StatusSeeOther)
}

func (s *Server) doDeleteForm(w http.ResponseWriter, r *http.Request, root *jail.Root, prefix, rel, name string) {
	var ok bool
	name, ok = entryName(name)
	if !ok {
		http.Error(w, "invalid name", http.StatusBadRequest)
		return
	}
	dest := path.Join(rel, name)
	s.serveDelete(w, r, root, dest, listingURL(prefix, rel))
}

func (s *Server) serveDelete(w http.ResponseWriter, r *http.Request, root *jail.Root, rel, redirect string) {
	rel = strings.Trim(rel, "/")
	if rel == "" || rel == "." {
		http.Error(w, "cannot delete tree root", http.StatusBadRequest)
		return
	}
	if err := root.Remove(rel); err != nil {
		if err == jail.ErrNotEmpty {
			http.Error(w, "directory not empty", http.StatusConflict)
			return
		}
		statusFromJail(w, err)
		return
	}
	if redirect != "" {
		http.Redirect(w, r, redirect, http.StatusSeeOther)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) chownRel(root *jail.Root, rel, pamUser string) {
	acct, err := pamauth.Lookup(pamUser)
	if err != nil {
		return
	}
	gid := acct.GID
	if g, err := pamauth.LookupGroupGID(s.config().UnixGroup); err == nil {
		gid = g
	}
	if err := root.Chown(rel, acct.UID, gid); err != nil {
		log.Printf("chown %s: %v", rel, err)
	}
}

func listingURL(prefix, rel string) string {
	return strings.TrimSuffix(prefix+"/"+rel, "/") + "/"
}

func entryName(name string) (string, bool) {
	name = path.Base(name)
	if name == "." || name == ".." || name == "" {
		return "", false
	}
	return name, true
}

func statusFromJail(w http.ResponseWriter, err error) {
	if jail.IsNotExist(err) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err == jail.ErrEscape || err == jail.ErrInvalid {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	http.Error(w, "forbidden", http.StatusForbidden)
}
