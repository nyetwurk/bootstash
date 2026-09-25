// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package web

import (
	"bytes"
	"encoding/json"
	"errors"
	"html/template"
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

// isAdmin is the current seam: ADMIN_USERS in operator config, linked PAM name, live config.
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
	ctype := fileContentType(info.Name())
	disp := contentDisposition(ctype)
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

const ovpnImportMax = 1 << 20

const ovpnImportPage = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>OpenVPN</title></head>
<body>
<script>
(function () {
  var msg = __MSG__;
  if (window.appEvent && appEvent.postMessage) appEvent.postMessage(msg);
  else if (window.parent !== window) window.parent.postMessage(msg, "*");
})();
</script>
<p>Profile sent to OpenVPN.</p>
</body>
</html>
`

func (s *Server) serveOpenVPNProfile(w http.ResponseWriter, r *http.Request) {
	sess := s.session(r)
	if sess == nil || sess.PAMUser == "" {
		log.Printf("openvpn GET %s from %s: session lost -> /login", r.URL.RequestURI(), r.RemoteAddr)
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	s.prepareCubbyRead(sess.PAMUser, "")
	rootPath, err := s.jailPath(sess)
	if err != nil {
		log.Printf("openvpn GET %s pam=%s from %s: jail path: %v", r.URL.RequestURI(), sess.PAMUser, r.RemoteAddr, err)
		s.replyError(w, r, http.StatusNotFound, "Could not open your files.")
		return
	}
	root, err := jail.OpenRoot(rootPath)
	if err != nil {
		log.Printf("openvpn GET %s pam=%s from %s: open cubby: %v", r.URL.RequestURI(), sess.PAMUser, r.RemoteAddr, err)
		s.replyError(w, r, http.StatusNotFound, "Could not open your files.")
		return
	}
	defer root.Close()
	found := collectOvpn(root)
	rel := requestedOvpn(found, r.URL.Query().Get("profile"))
	if r.URL.Query().Get("embedded") == "true" {
		if rel == "" {
			log.Printf("openvpn GET %s pam=%s from %s ua=%q: embedded no profile found=%q -> /home/", r.URL.RequestURI(), sess.PAMUser, r.RemoteAddr, r.UserAgent(), found)
			http.Redirect(w, r, "/home/", http.StatusFound)
			return
		}
		f, err := root.Open(rel)
		if err != nil {
			log.Printf("openvpn GET %s pam=%s from %s: open %s: %v -> /home/", r.URL.RequestURI(), sess.PAMUser, r.RemoteAddr, rel, err)
			http.Redirect(w, r, "/home/", http.StatusFound)
			return
		}
		defer f.Close()
		body, err := io.ReadAll(io.LimitReader(f, ovpnImportMax+1))
		if err != nil || int64(len(body)) > ovpnImportMax {
			log.Printf("openvpn GET %s pam=%s from %s: read %s: %v len=%d", r.URL.RequestURI(), sess.PAMUser, r.RemoteAddr, rel, err, len(body))
			s.replyError(w, r, http.StatusInternalServerError, "Something went wrong.")
			return
		}
		payload, err := json.Marshal(map[string]any{
			"type": "PROFILE_DOWNLOAD_SUCCESS",
			"data": map[string]string{"profile": string(ovpnTitledProfile(rel, body)), "title": ovpnDisplayName(rel, body)},
		})
		if err != nil {
			s.replyError(w, r, http.StatusInternalServerError, "Something went wrong.")
			return
		}
		log.Printf("openvpn GET %s pam=%s from %s ua=%q: embedded %s %d bytes found=%q", r.URL.RequestURI(), sess.PAMUser, r.RemoteAddr, r.UserAgent(), rel, len(body), found)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, strings.Replace(ovpnImportPage, "__MSG__", string(payload), 1))
		return
	}
	if wantsHTML(r) && r.URL.Query().Get("download") != "1" {
		s.renderOvpnHandoff(w, r, sess, found, rel)
		return
	}
	if rel == "" {
		log.Printf("openvpn GET %s pam=%s from %s ua=%q: no profile found=%q -> /home/", r.URL.RequestURI(), sess.PAMUser, r.RemoteAddr, r.UserAgent(), found)
		http.Redirect(w, r, "/home/", http.StatusFound)
		return
	}
	if err := s.writeOvpnAttachment(w, r, sess.PAMUser, rel); err != nil {
		log.Printf("openvpn GET %s pam=%s from %s: serve %s: %v -> /home/", r.URL.RequestURI(), sess.PAMUser, r.RemoteAddr, rel, err)
		http.Redirect(w, r, "/home/", http.StatusFound)
		return
	}
	log.Printf("openvpn GET %s pam=%s from %s ua=%q accept=%q: attachment %s type=%s found=%q", r.URL.RequestURI(), sess.PAMUser, r.RemoteAddr, r.UserAgent(), r.Header.Get("Accept"), rel, ovpnProfileType, found)
}

func (s *Server) tryOvpnImport(r *http.Request, pam, rel, sid string) template.URL {
	id, err := s.putOvpnTicket(pam, rel, sid)
	if err != nil {
		log.Printf("openvpn GET %s pam=%s from %s: ticket %s: %v", r.URL.RequestURI(), pam, r.RemoteAddr, rel, err)
		return ""
	}
	return template.URL("openvpn://import-profile/" + s.config().PublicURL + "/openvpn-api/profile?token=" + id)
}

func (s *Server) renderOvpnHandoff(w http.ResponseWriter, r *http.Request, sess *store.Session, found []string, rel string) {
	data := sessionPage(sess, pageData{Title: "OpenVPN"})
	tokens := !s.ovpnTokensOff(sess.PAMUser)
	data.OvpnToken = tokens
	switch {
	case rel != "":
		data.File = path.Base(rel)
		data.Download = ovpnProfileDownloadURI(r, rel)
		if tokens {
			data.Import = s.tryOvpnImport(r, sess.PAMUser, rel, sess.ID)
		}
		log.Printf("openvpn GET %s pam=%s from %s ua=%q: html handoff %s import=%v found=%q", r.URL.RequestURI(), sess.PAMUser, r.RemoteAddr, r.UserAgent(), rel, data.Import != "", found)
	case len(found) > 0:
		sorted := append([]string(nil), found...)
		sort.Strings(sorted)
		for _, p := range sorted {
			ch := ovpnChoice{Name: p, Download: ovpnProfileDownloadURI(r, p)}
			if tokens {
				imp := s.tryOvpnImport(r, sess.PAMUser, p, sess.ID)
				if imp == "" {
					continue
				}
				ch.Import = imp
			}
			data.Choices = append(data.Choices, ch)
		}
		log.Printf("openvpn GET %s pam=%s from %s ua=%q: html picker n=%d tokens=%v found=%q", r.URL.RequestURI(), sess.PAMUser, r.RemoteAddr, r.UserAgent(), len(data.Choices), tokens, found)
	default:
		log.Printf("openvpn GET %s pam=%s from %s ua=%q: html empty", r.URL.RequestURI(), sess.PAMUser, r.RemoteAddr, r.UserAgent())
	}
	s.render(w, "ovpn", data)
}

func (s *Server) serveOpenVPNTicket(w http.ResponseWriter, r *http.Request, id string) {
	t, ok := s.peekOvpnTicket(id)
	if ok && !s.ovpnTicketSessionOK(t) {
		s.dropOvpnTicket(id)
		log.Printf("openvpn token %s pam=%s from %s ua=%q: session gone %s", r.Method, t.pam, r.RemoteAddr, r.UserAgent(), t.rel)
		http.NotFound(w, r)
		return
	}
	if ok && r.Method != http.MethodHead {
		t, ok = s.takeOvpnTicket(id)
	}
	if !ok {
		log.Printf("openvpn token %s from %s ua=%q: missing", r.Method, r.RemoteAddr, r.UserAgent())
		http.NotFound(w, r)
		return
	}
	if s.ovpnTokensOff(t.pam) {
		log.Printf("openvpn token %s pam=%s from %s ua=%q: disabled %s", r.Method, t.pam, r.RemoteAddr, r.UserAgent(), t.rel)
		http.NotFound(w, r)
		return
	}
	if err := s.writeOvpnAttachment(w, r, t.pam, t.rel); err != nil {
		log.Printf("openvpn token %s pam=%s from %s ua=%q: %s: %v", r.Method, t.pam, r.RemoteAddr, r.UserAgent(), t.rel, err)
		http.NotFound(w, r)
		return
	}
	log.Printf("openvpn token %s pam=%s from %s ua=%q: %s", r.Method, t.pam, r.RemoteAddr, r.UserAgent(), t.rel)
}

func (s *Server) writeOvpnAttachment(w http.ResponseWriter, r *http.Request, pam, rel string) error {
	if !pamauth.ValidUsername(pam) || rel == "" || !filepath.IsLocal(rel) {
		return os.ErrNotExist
	}
	s.prepareCubbyRead(pam, rel)
	rootPath, err := s.jailPath(&store.Session{PAMUser: pam})
	if err != nil {
		return err
	}
	root, err := jail.OpenRoot(rootPath)
	if err != nil {
		return err
	}
	defer root.Close()
	info, err := root.Stat(rel)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return os.ErrNotExist
	}
	f, err := root.Open(rel)
	if err != nil {
		return err
	}
	defer f.Close()
	name := path.Base(rel)
	body, err := io.ReadAll(io.LimitReader(f, ovpnImportMax+1))
	if err != nil {
		return err
	}
	if int64(len(body)) > ovpnImportMax {
		return io.ErrUnexpectedEOF
	}
	out := ovpnTitledProfile(rel, body)
	w.Header().Set("Content-Type", ovpnProfileType)
	cd := mime.FormatMediaType("attachment", map[string]string{"filename": name})
	if cd == "" {
		cd = "attachment"
	}
	w.Header().Set("Content-Disposition", cd)
	w.Header().Set("Content-Length", strconv.Itoa(len(out)))
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return nil
	}
	_, err = w.Write(out)
	return err
}

func ovpnFileLabel(rel string) string {
	name := ovpnCleanLabel(strings.TrimSuffix(rel, path.Ext(rel)))
	if name == "" {
		return "profile"
	}
	return name
}

// ovpnCleanLabel keeps a display label safe inside an OpenVPN comment
// and a double-quoted setenv value. Anything outside the allowlist,
// including backslash, becomes '_'.
func ovpnCleanLabel(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		case r == ' ' || r == '.' || r == '_' || r == '-':
			return r
		default:
			return '_'
		}
	}, s)
}

func ovpnRemoteHost(body []byte) string {
	for _, raw := range bytes.Split(body, []byte("\n")) {
		line := strings.TrimSpace(string(raw))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && strings.EqualFold(fields[0], "remote") {
			return ovpnCleanLabel(fields[1])
		}
	}
	return ""
}

func ovpnDisplayName(rel string, body []byte) string {
	name := ovpnFileLabel(rel)
	host := ovpnRemoteHost(body)
	if host == "" || host == name {
		return name
	}
	return host + " [" + name + "]"
}

func ovpnTitledProfile(rel string, body []byte) []byte {
	if bytes.Contains(body, []byte("OVPN_ACCESS_SERVER_FRIENDLY_NAME=")) || bytes.Contains(body, []byte("setenv FRIENDLY_NAME")) {
		return body
	}
	title := ovpnDisplayName(rel, body)
	var b bytes.Buffer
	b.Grow(len(body) + 96)
	_, _ = b.WriteString("# OVPN_ACCESS_SERVER_FRIENDLY_NAME=")
	_, _ = b.WriteString(title)
	_, _ = b.WriteString("\n# OVPN_ACCESS_SERVER_PROFILE=")
	_, _ = b.WriteString(title)
	_, _ = b.WriteString("\nsetenv FRIENDLY_NAME \"")
	_, _ = b.WriteString(title)
	_, _ = b.WriteString("\"\n")
	_, _ = b.Write(body)
	return b.Bytes()
}

func ovpnProfileDownloadURI(r *http.Request, rel string) string {
	q := r.URL.Query()
	q.Set("download", "1")
	q.Del("embedded")
	q.Del("token")
	if rel != "" {
		q.Set("profile", rel)
	} else {
		q.Del("profile")
	}
	path := r.URL.Path
	if path == "" {
		path = "/openvpn-api/profile"
	}
	return path + "?" + q.Encode()
}

// ovpnTokenSentinel in the cubby root turns off Connect capability URLs
// for that PAM user. Presence of a regular file; content is ignored.
const ovpnTokenSentinel = ".bootstash-no-ovpn-token"

func (s *Server) ovpnTokensOff(pam string) bool {
	if s.config().DisableOvpnToken {
		return true
	}
	if pam == "" || !pamauth.ValidUsername(pam) {
		return false
	}
	rootPath, err := s.jailPath(&store.Session{PAMUser: pam})
	if err != nil {
		return true
	}
	root, err := jail.OpenRoot(rootPath)
	if err != nil {
		return true
	}
	defer root.Close()
	st, err := root.Stat(ovpnTokenSentinel)
	if err != nil {
		if jail.IsNotExist(err) {
			return false
		}
		return true
	}
	return st.Mode().IsRegular()
}

func requestedOvpn(found []string, want string) string {
	if want == "" {
		return pickOvpn(found)
	}
	want = path.Clean(want)
	for _, p := range found {
		if p == want {
			return p
		}
	}
	return ""
}

func collectOvpn(root *jail.Root) []string {
	var out []string
	var walk func(rel string, depth int)
	walk = func(rel string, depth int) {
		if depth > 4 || len(out) >= 32 {
			return
		}
		infos, err := root.ReadDirNames(rel)
		if err != nil {
			return
		}
		for _, fi := range infos {
			if fi.Mode()&os.ModeSymlink != 0 {
				continue
			}
			name := fi.Name()
			child := name
			if rel != "" {
				child = path.Join(rel, name)
			}
			if fi.IsDir() {
				walk(child, depth+1)
				continue
			}
			if strings.EqualFold(path.Ext(name), ".ovpn") {
				out = append(out, child)
			}
		}
	}
	walk("", 0)
	return out
}

func pickOvpn(paths []string) string {
	if len(paths) == 1 {
		return paths[0]
	}
	var clients []string
	for _, p := range paths {
		if strings.EqualFold(path.Base(p), "client.ovpn") {
			clients = append(clients, p)
		}
	}
	if len(clients) == 1 {
		return clients[0]
	}
	return ""
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
