// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/nyet/bootstash/internal/config"
	"github.com/nyet/bootstash/internal/pamauth"
)

func runProvision(args []string) int {
	fs := flag.NewFlagSet("provision-google", flag.ExitOnError)
	cfgFile := fs.String("config", config.DefaultConfigPath, "operator config (read PUBLIC_ORIGIN)")
	secretsFile := fs.String("secrets", config.DefaultSecretsPath, "OIDC client secrets file to write")
	origin := fs.String("origin", "", "PUBLIC_ORIGIN (default: read from operator config)")
	project := fs.String("project", "", "GCP project id for console URLs")
	jsonPath := fs.String("json", "", "downloaded Google Web application client JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg, err := config.Load(config.DefaultDistPath, *cfgFile, *secretsFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	pub := *origin
	if pub == "" {
		pub = cfg.PublicOrigin
	}
	if pub == "" {
		fmt.Fprintln(os.Stderr, "PUBLIC_ORIGIN is not set; pass -origin, add it to", *cfgFile, ", or give hostname -f a usable name")
		return 1
	}
	pub = strings.TrimRight(pub, "/")
	redirect := pub + "/oidc/callback"
	proj := *project
	if proj == "" {
		proj = gcloudValue("config", "get-value", "project")
	}
	printGoogleSetup(os.Stdout, googleSetup{
		Pub:       pub,
		Redirect:  redirect,
		Proj:      proj,
		TLS:       cfg.TLSCert != "" && cfg.TLSKey != "",
		CertName:  cfg.CertName,
		Binds:     cfg.Binds,
		OriginSet: *origin != "",
	})

	src := *jsonPath
	if src == "" {
		in := bufio.NewReader(os.Stdin)
		p, err := prompt(in, "Path to downloaded client JSON: ")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		src = p
	}
	if src == "" {
		fmt.Fprintln(os.Stderr, "no client JSON path; pass -json or download the Web application JSON")
		return 1
	}
	if err := installGoogleClientJSON(src, *secretsFile, cfg.UnixGroup); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Println("Installed Google client JSON at", *secretsFile)
	return 0
}

type googleSetup struct {
	Pub       string
	Redirect  string
	Proj      string
	TLS       bool
	CertName  string
	Binds     []string
	OriginSet bool
}

func printGoogleSetup(w io.Writer, s googleSetup) {
	q := ""
	if s.Proj != "" {
		q = "?project=" + s.Proj
	}

	fmt.Fprintln(w, "1. GCP project (once)")
	fmt.Fprintln(w, "   https://console.cloud.google.com/cloud-resource-manager"+q)
	fmt.Fprintln(w, "   Recommend: display name bootstash. Project id bootstash if free;")
	fmt.Fprintln(w, "   otherwise bootstash-<tag>. One project is enough. Not the hostname.")
	if s.Proj != "" {
		fmt.Fprintln(w, "   Current gcloud project:", s.Proj)
	} else {
		fmt.Fprintln(w, "   No gcloud project; pass -project ID or: gcloud auth login")
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "2. Branding / consent screen (once per project)")
	fmt.Fprintln(w, "   https://console.cloud.google.com/auth/branding"+q)
	fmt.Fprintln(w, "   Recommend: External. Testing. App name bootstash. Support email = you.")
	fmt.Fprintln(w, "   Add your Google account as a test user. Skip verification unless any")
	fmt.Fprintln(w, "   Google account must work.")
	fmt.Fprintln(w)

	fmt.Fprintln(w, "3. OAuth client (one per PUBLIC_ORIGIN)")
	fmt.Fprintln(w, "   https://console.cloud.google.com/auth/clients"+q)
	fmt.Fprintln(w, "   Recommend: type Web application. Name can be bootstash or the host.")
	fmt.Fprintln(w, "   Authorized redirect URI (exact, $PUBLIC_ORIGIN/oidc/callback):")
	fmt.Fprintln(w, "    ", s.Redirect)
	fmt.Fprintln(w, "   Paste that character-for-character. Leave other client fields empty.")
	fmt.Fprintln(w, "   Authorized JavaScript origins: leave empty, or")
	fmt.Fprintln(w, "    ", s.Pub)
	fmt.Fprintln(w, "   with no path.")
	if s.OriginSet {
		fmt.Fprintln(w, "   PUBLIC_ORIGIN came from -origin.")
	} else if s.TLS {
		fmt.Fprintln(w, "   HTTPS: PEMs found under /etc/bootstash/certs (TCP binds already")
		fmt.Fprintln(w, "   speak HTTPS). Finding certs does not change BIND or move the port")
		fmt.Fprintln(w, "   to 443. The port in the URI is BIND ("+strings.Join(s.Binds, ", ")+").")
		if s.CertName != "" {
			fmt.Fprintln(w, "   CERT_NAME="+s.CertName)
		}
		fmt.Fprintln(w, "   Phone on default HTTPS: set BIND (e.g. *:443) and run this again.")
	} else {
		fmt.Fprintln(w, "   HTTP: no PEMs in /etc/bootstash/certs. Do not invent https://.")
		fmt.Fprintln(w, "   To use HTTPS: CERT_NAME=<lineage> in /etc/default/bootstash, then")
		fmt.Fprintln(w, "   sudo /usr/lib/bootstash/letsencrypt-deploy sync, then run this again.")
		fmt.Fprintln(w, "   Do not point TLS_* at /etc/letsencrypt/live.")
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "4. Download the client JSON from the console (Download JSON). That file")
	fmt.Fprintln(w, "   has web.client_id and web.client_secret. Not your Google account.")
	fmt.Fprintln(w, "   This command copies it to /etc/bootstash/oidc-google.json (needs root).")
	fmt.Fprintln(w, "   It does not write TLS certs and does not create the Google client")
	fmt.Fprintln(w, "   (gcloud has no API for that type).")
	fmt.Fprintln(w)
}

func prompt(in *bufio.Reader, label string) (string, error) {
	fmt.Fprint(os.Stderr, label)
	line, err := in.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func gcloudValue(args ...string) string {
	path, err := exec.LookPath("gcloud")
	if err != nil {
		return ""
	}
	cmd := exec.Command(path, args...)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	v := strings.TrimSpace(string(out))
	if v == "" || v == "(unset)" {
		return ""
	}
	return v
}

func installGoogleClientJSON(src, dest, group string) error {
	var b []byte
	var err error
	if src == "-" {
		b, err = io.ReadAll(os.Stdin)
	} else {
		b, err = os.ReadFile(src)
	}
	if err != nil {
		return err
	}
	_, secret, err := config.ParseGoogleClientJSON(b)
	if err != nil {
		return err
	}
	if secret == "" {
		return fmt.Errorf("Google client JSON: missing web.client_secret")
	}
	dir := filepath.Dir(dest)
	_, err = os.Stat(dir)
	created := os.IsNotExist(err)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return err
	}
	if created || dir == filepath.Dir(config.DefaultSecretsPath) {
		if err := os.Chmod(dir, 0750); err != nil {
			return err
		}
		_ = chownGroup(dir, group)
	}
	tmp := dest + ".tmp"
	if err := os.WriteFile(tmp, b, 0640); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0640); err != nil {
		return err
	}
	_ = chownGroup(tmp, group)
	if err := os.Rename(tmp, dest); err != nil {
		return err
	}
	if err := os.Chmod(dest, 0640); err != nil {
		return err
	}
	_ = chownGroup(dest, group)
	return nil
}

func chownGroup(path, group string) error {
	if group == "" {
		group = "bootstash"
	}
	gid, err := pamauth.LookupGroupGID(group)
	if err != nil {
		return err
	}
	return os.Chown(path, -1, gid)
}
