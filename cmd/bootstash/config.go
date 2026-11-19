// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"go.nyet.org/bootstash/internal/config"
)

func runConfig(args []string) int {
	return printConfig(os.Stdout, args)
}

func printConfig(w io.Writer, args []string) int {
	fs := flag.NewFlagSet("config", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	defaults := fs.String("defaults", config.DefaultDistPath, "dist defaults")
	cfgFile := fs.String("config", config.DefaultConfigPath, "operator config")
	secretsFile := fs.String("secrets", config.DefaultSecretsPath, "OIDC client JSON (secret is not printed)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: bootstash config [-defaults path] [-config path] [-secrets path]")
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(os.Stderr, "bootstash config: unknown argument %q\n", fs.Arg(0))
		return 2
	}
	cfg, err := config.Load(*defaults, *cfgFile, *secretsFile)
	if err != nil {
		// The operator file is 0644. The client JSON may be unreadable
		// by the user who only needs PAM and ALLOWED_EMAILS.
		op, oerr := config.LoadOperator(*defaults, *cfgFile)
		if oerr != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Fprintln(os.Stderr, "bootstash config:", err)
		cfg = op
	}
	if _, err := io.WriteString(w, cfg.Format()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}
