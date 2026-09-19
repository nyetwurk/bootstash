// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package web

import (
	"errors"
	"io"
	"log"
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/nyet/bootstash/internal/jail"
	"github.com/nyet/bootstash/internal/pamauth"
	"github.com/nyet/bootstash/internal/store"
)

func (s *Server) handleFiles(w http.ResponseWriter, r *http.Request) {
	sess := s.session(r)
	if sess == nil || sess.PAMUser == "" {
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			loc := "/login"
			if sess != nil {
				loc = "/link"
			}
			http.Redirect(w, r, loc, http.StatusFound)
			return
		}
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
		s.replyError(w, r, http.StatusNotFound, "Could not open your files.")
		return
	}
	root, err := jail.OpenRoot(rootPath)
	if err != nil {
		s.replyError(w, r, http.StatusNotFound, "Could not open your files.")
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
		s.cubbyErr(w, r, prefix, rel, err)
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
		s.cubbyErr(w, r, prefix, rel, err)
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
	cd := mime.FormatMediaType(disp, map[string]string{"filename": info.Name()})
	if cd == "" {
		cd = disp
	}
	w.Header().Set("Content-Disposition", cd)
	if r.Method == http.MethodGet && wantsHTML(r) && disp == "attachment" {
		s.setDownloadMark(w, rel)
	}
	http.ServeContent(w, r, info.Name(), info.ModTime(), f)
}

func (s *Server) serveListing(w http.ResponseWriter, r *http.Request, root *jail.Root, prefix, rel string) {
	infos, err := root.ReadDirNames(rel)
	if err != nil {
		s.cubbyErr(w, r, prefix, rel, err)
		return
	}
	sort.Slice(infos, func(i, j int) bool {
		if infos[i].IsDir() != infos[j].IsDir() {
			return infos[i].IsDir()
		}
		return infos[i].Name() < infos[j].Name()
	})
	base := strings.TrimSuffix(prefix+"/"+rel, "/")
	if rel == "" {
		base = prefix
	}
	marked := s.takeDownloadMark(w, r, rel)
	var entries []listEntry
	for _, fi := range infos {
		name := fi.Name()
		href := path.Join(base, name)
		if fi.IsDir() {
			href += "/"
		}
		entries = append(entries, listEntry{
			Name:    name,
			Href:    href,
			Size:    formatSize(fi.Size()),
			Date:    formatDate(fi.ModTime()),
			DateISO: fi.ModTime().UTC().Format(time.RFC3339),
			Dir:     fi.IsDir(),
			Link:    fi.Mode()&os.ModeSymlink != 0,
			Mark:    !fi.IsDir() && name == marked,
		})
	}
	heading := "Files"
	var crumbs []crumb
	if rel != "" {
		heading = path.Base(rel)
		crumbs = []crumb{{Name: "Files", Href: prefix + "/"}}
		acc := ""
		parts := strings.Split(rel, "/")
		for i, p := range parts {
			if p == "" || p == "." {
				continue
			}
			acc = path.Join(acc, p)
			c := crumb{Name: p}
			if i < len(parts)-1 {
				c.Href = prefix + "/" + acc + "/"
			}
			crumbs = append(crumbs, c)
		}
	}
	errMsg := s.takeNotice(w, r)
	s.render(w, "listing", sessionPage(s.session(r), pageData{
		Title:    heading,
		Error:    errMsg,
		Crumbs:   crumbs,
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
	if err := root.Replace(rel, 0660, r.Body); err != nil {
		if isUploadTooLarge(err) {
			http.Error(w, "upload failed", http.StatusRequestEntityTooLarge)
			return
		}
		statusFromJail(w, err)
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
			s.formFail(w, r, prefix, rel, "too-large", "upload too large", http.StatusRequestEntityTooLarge)
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
			s.formFail(w, r, prefix, rel, "need-file", "file required", http.StatusBadRequest)
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
			s.formFail(w, r, prefix, rel, "bad-name", "invalid name", http.StatusBadRequest)
			return
		}
		dest := path.Join(rel, name)
		if err := root.Replace(dest, 0660, fh); err != nil {
			if isUploadTooLarge(err) {
				s.formFail(w, r, prefix, rel, "too-large", "upload failed", http.StatusRequestEntityTooLarge)
				return
			}
			s.jailFail(w, r, prefix, rel, err)
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
	s.replyError(w, r, http.StatusBadRequest, "That request was not understood.")
}

func (s *Server) doMkdir(w http.ResponseWriter, r *http.Request, root *jail.Root, prefix, rel, name string, sess *store.Session) {
	if name == "" {
		name = path.Base(strings.TrimSuffix(rel, "/"))
		if rel == "" || name == "." || name == "/" {
			s.formFail(w, r, prefix, rel, "need-name", "name required", http.StatusBadRequest)
			return
		}
		if err := root.Mkdir(rel, 0770); err != nil {
			s.jailFail(w, r, prefix, rel, err)
			return
		}
		s.chownRel(root, rel, sess.PAMUser)
		w.WriteHeader(http.StatusCreated)
		return
	}
	name, ok := entryName(name)
	if !ok {
		s.formFail(w, r, prefix, rel, "bad-name", "invalid name", http.StatusBadRequest)
		return
	}
	dest := path.Join(rel, name)
	if err := root.Mkdir(dest, 0770); err != nil {
		s.jailFail(w, r, prefix, rel, err)
		return
	}
	s.chownRel(root, dest, sess.PAMUser)
	http.Redirect(w, r, listingURL(prefix, rel), http.StatusSeeOther)
}

func (s *Server) doDeleteForm(w http.ResponseWriter, r *http.Request, root *jail.Root, prefix, rel, name string) {
	var ok bool
	name, ok = entryName(name)
	if !ok {
		s.formFail(w, r, prefix, rel, "bad-name", "invalid name", http.StatusBadRequest)
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
			if redirect != "" {
				s.setNotice(w, "not-empty")
				http.Redirect(w, r, redirect, http.StatusSeeOther)
				return
			}
			http.Error(w, "directory not empty", http.StatusConflict)
			return
		}
		if redirect != "" {
			s.setNotice(w, jailErrKey(err))
			http.Redirect(w, r, redirect, http.StatusSeeOther)
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
	if err != nil || !pamauth.Linkable(acct) {
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

func downloadNameIn(listingRel, fileRel string) string {
	fileRel = strings.Trim(fileRel, "/")
	listingRel = strings.Trim(listingRel, "/")
	dir := path.Dir(fileRel)
	if dir == "." {
		dir = ""
	}
	if dir != listingRel {
		return ""
	}
	name := path.Base(fileRel)
	if name == "." || name == "/" || name == "" {
		return ""
	}
	return name
}

func listingURL(prefix, rel string) string {
	return strings.TrimSuffix(prefix+"/"+rel, "/") + "/"
}

func parentListing(prefix, rel string) string {
	rel = strings.Trim(rel, "/")
	parent := path.Dir(rel)
	if rel == "" || parent == "." || parent == "/" {
		return prefix + "/"
	}
	return listingURL(prefix, parent)
}

func (s *Server) formFail(w http.ResponseWriter, r *http.Request, prefix, rel, key, plain string, status int) {
	if wantsHTML(r) {
		s.setNotice(w, key)
		http.Redirect(w, r, listingURL(prefix, rel), http.StatusSeeOther)
		return
	}
	http.Error(w, plain, status)
}

func (s *Server) jailFail(w http.ResponseWriter, r *http.Request, prefix, rel string, err error) {
	if wantsHTML(r) {
		s.setNotice(w, jailErrKey(err))
		http.Redirect(w, r, listingURL(prefix, rel), http.StatusSeeOther)
		return
	}
	statusFromJail(w, err)
}

func wantsHTML(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

func (s *Server) cubbyErr(w http.ResponseWriter, r *http.Request, prefix, rel string, err error) {
	if r.Method == http.MethodGet && wantsHTML(r) {
		if strings.Trim(rel, "/") != "" {
			s.setNotice(w, jailErrKey(err))
			http.Redirect(w, r, parentListing(prefix, rel), http.StatusSeeOther)
			return
		}
		msg := listingErrMessage(jailErrKey(err))
		if msg == "" {
			msg = "Could not open that."
		}
		code, _ := jailHTTP(err)
		s.replyError(w, r, code, msg)
		return
	}
	statusFromJail(w, err)
}

func listingErrMessage(key string) string {
	switch key {
	case "not-empty":
		return "That folder still has files in it."
	case "not-allowed":
		return "That path is not allowed."
	case "denied":
		return "Not authorized to open that."
	case "missing":
		return "That file is gone."
	case "not-a-folder":
		return "That is not a folder."
	case "failed":
		return "Could not open that."
	case "too-large":
		return "That file is too large."
	case "need-file":
		return "Choose a file to upload."
	case "bad-name":
		return "That name is not allowed."
	case "need-name":
		return "Name required."
	default:
		return ""
	}
}

func jailErrKey(err error) string {
	switch {
	case errors.Is(err, jail.ErrEscape), errors.Is(err, jail.ErrInvalid):
		return "not-allowed"
	case errors.Is(err, syscall.EACCES), errors.Is(err, syscall.EPERM):
		return "denied"
	case jail.IsNotExist(err):
		return "missing"
	case errors.Is(err, jail.ErrNotDir), errors.Is(err, syscall.ENOTDIR):
		return "not-a-folder"
	default:
		return "failed"
	}
}

func entryName(name string) (string, bool) {
	name = path.Base(name)
	if name == "." || name == ".." || name == "" {
		return "", false
	}
	return name, true
}

func isUploadTooLarge(err error) bool {
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) {
		return true
	}
	return errors.Is(err, io.ErrUnexpectedEOF)
}

func jailHTTP(err error) (int, string) {
	if jail.IsNotExist(err) {
		return http.StatusNotFound, "not found"
	}
	if errors.Is(err, jail.ErrEscape) || errors.Is(err, jail.ErrInvalid) {
		return http.StatusBadRequest, "invalid path"
	}
	if errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) {
		return http.StatusForbidden, "not authorized"
	}
	if errors.Is(err, jail.ErrNotDir) || errors.Is(err, syscall.ENOTDIR) {
		return http.StatusBadRequest, "not a directory"
	}
	return http.StatusForbidden, "forbidden"
}

func statusFromJail(w http.ResponseWriter, err error) {
	code, msg := jailHTTP(err)
	http.Error(w, msg, code)
}
