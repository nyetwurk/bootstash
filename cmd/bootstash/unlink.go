// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/nyet/bootstash/internal/config"
	"github.com/nyet/bootstash/internal/pamauth"
	"github.com/nyet/bootstash/internal/store"
)

func runUnlink(args []string) int {
	fs := flag.NewFlagSet("unlink", flag.ExitOnError)
	defaults := fs.String("defaults", config.DefaultDistPath, "dist defaults (read DATA)")
	cfgFile := fs.String("config", config.DefaultConfigPath, "operator config (read DATA)")
	secretsFile := fs.String("secrets", config.DefaultSecretsPath, "OIDC client secrets")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: bootstash unlink [options] USER")
		return 2
	}
	user := fs.Arg(0)
	if !pamauth.ValidUsername(user) {
		fmt.Fprintf(os.Stderr, "bootstash unlink: invalid user %q\n", user)
		return 2
	}

	cfg, err := config.Load(*defaults, *cfgFile, *secretsFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	st, err := store.Open(cfg.Data)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	removed, sessions, err := st.UnlinkPAM(user)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if len(removed) == 0 && sessions == 0 {
		fmt.Fprintf(os.Stderr, "bootstash unlink: no links for %s\n", user)
		return 1
	}
	fmt.Printf("unlinked %s (%d subject(s), %d session(s))\n", user, len(removed), sessions)
	for _, l := range removed {
		log.Printf("unlink pam=%s sub=%s", user, l.Subject)
		fmt.Printf("  %s %s\n", l.Issuer, l.Subject)
	}
	if len(removed) == 0 && sessions > 0 {
		log.Printf("unlink pam=%s sessions=%d", user, sessions)
	}
	return 0
}
