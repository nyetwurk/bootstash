// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bufio"
	"flag"
	"fmt"
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
	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg, err := config.Load(config.DefaultDefaultsPath, *cfgFile, *secretsFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	pub := *origin
	if pub == "" {
		pub = cfg.PublicOrigin
	}
	if pub == "" {
		fmt.Fprintln(os.Stderr, "PUBLIC_ORIGIN is not set; pass -origin or add it to", *cfgFile)
		return 1
	}
	pub = strings.TrimRight(pub, "/")
	redirect := pub + "/oidc/callback"
	fmt.Println("Redirect URI (paste into the Google web client):")
	fmt.Println(" ", redirect)
	fmt.Println()

	proj := *project
	if proj == "" {
		proj = gcloudValue("config", "get-value", "project")
	}
	q := ""
	if proj != "" {
		q = "?project=" + proj
		fmt.Println("gcloud project:", proj)
	} else {
		fmt.Println("gcloud not logged in or no project; pass -project ID.")
		fmt.Println("If needed: gcloud auth login")
	}
	fmt.Println()
	fmt.Println("Google Auth Platform (branding, once per project):")
	fmt.Println("  https://console.cloud.google.com/auth/branding" + q)
	fmt.Println("Create a Web application OAuth client:")
	fmt.Println("  https://console.cloud.google.com/auth/clients" + q)
	fmt.Println("Authorized redirect URI must be exactly the URI above.")
	fmt.Println()

	in := bufio.NewReader(os.Stdin)
	id, err := prompt(in, "Client ID: ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	secret, err := prompt(in, "Client secret: ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := writeSecretsFile(*secretsFile, map[string]string{
		"OIDC_GOOGLE_CLIENT_ID":     id,
		"OIDC_GOOGLE_CLIENT_SECRET": secret,
	}, cfg.UnixGroup); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Println("Wrote client id/secret to", *secretsFile)
	return 0
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

var secretKeyOrder = []string{
	"OIDC_GOOGLE_CLIENT_ID",
	"OIDC_GOOGLE_CLIENT_SECRET",
}

func writeSecretsFile(path string, keys map[string]string, group string) error {
	var lines []string
	if b, err := os.ReadFile(path); err == nil {
		lines = strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
		if len(lines) == 1 && lines[0] == "" {
			lines = nil
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if len(lines) == 0 {
		lines = []string{
			"# Written by bootstash provision-google. Operator keys belong in /etc/default/bootstash.",
		}
	}
	seen := map[string]bool{}
	var out []string
	for _, line := range lines {
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") || !strings.Contains(trim, "=") {
			out = append(out, line)
			continue
		}
		k, _, _ := strings.Cut(trim, "=")
		k = strings.TrimSpace(k)
		if v, ok := keys[k]; ok {
			out = append(out, k+"="+v)
			seen[k] = true
			continue
		}
		out = append(out, line)
	}
	for _, k := range secretKeyOrder {
		v, ok := keys[k]
		if !ok || seen[k] {
			continue
		}
		out = append(out, k+"="+v)
	}
	dir := filepath.Dir(path)
	_, err := os.Stat(dir)
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
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strings.Join(out, "\n")+"\n"), 0640); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0640); err != nil {
		return err
	}
	_ = chownGroup(tmp, group)
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	if err := os.Chmod(path, 0640); err != nil {
		return err
	}
	_ = chownGroup(path, group)
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
