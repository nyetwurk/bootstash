// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/nyet/bootstash/internal/pamauth"
)

func runUnlink(args []string) int {
	fs := flag.NewFlagSet("unlink", flag.ExitOnError)
	defaults, cfgFile, secretsFile := stateFlags(fs)
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

	st, err := openState(*defaults, *cfgFile, *secretsFile)
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
	log.Printf("unlink pam=%s subjects=%d sessions=%d", user, len(removed), sessions)
	for _, l := range removed {
		log.Printf("unlink pam=%s sub=%s", user, l.Subject)
		fmt.Printf("  %s %s\n", l.Issuer, l.Subject)
	}
	return 0
}
