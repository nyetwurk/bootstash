//go:build cgo

// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

// bootstash-pam is the setuid PAM helper. Not an operator command.
// The daemon execs it as /usr/lib/bootstash/pam.
package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/nyet/bootstash/internal/pamauth"
)

func main() {
	os.Exit(run(os.Args, os.Stdin))
}

func run(args []string, stdin io.Reader) int {
	if len(args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: pam <service> <username>")
		return 2
	}
	pass, err := io.ReadAll(io.LimitReader(stdin, 8192))
	if err != nil {
		return 1
	}
	s := strings.TrimSuffix(string(pass), "\n")
	s = strings.TrimSuffix(s, "\r")
	if err := pamauth.Run(args[1], args[2], s); err != nil {
		return 1
	}
	return 0
}
