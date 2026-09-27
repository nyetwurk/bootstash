// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
)

func runLinks(args []string) int {
	return listLinks(os.Stdout, args)
}

func listLinks(w io.Writer, args []string) int {
	fs := flag.NewFlagSet("links", flag.ExitOnError)
	defaults, cfgFile, secretsFile := stateFlags(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: bootstash links [options]")
		return 2
	}

	st, err := openState(*defaults, *cfgFile, *secretsFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	links, err := st.ListLinks()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	sort.Slice(links, func(i, j int) bool {
		if links[i].PAMUser != links[j].PAMUser {
			return links[i].PAMUser < links[j].PAMUser
		}
		if links[i].Issuer != links[j].Issuer {
			return links[i].Issuer < links[j].Issuer
		}
		return links[i].Subject < links[j].Subject
	})
	for _, l := range links {
		fmt.Fprintf(w, "%s %s %s\n", l.PAMUser, l.Issuer, l.Subject)
	}
	return 0
}
