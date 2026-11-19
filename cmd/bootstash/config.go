// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"fmt"
	"io"
	"os"

	"go.nyet.org/bootstash/internal/config"
)

func runConfig(args []string) int {
	return printConfig(os.Stdout, args)
}

func printConfig(w io.Writer, args []string) int {
	defaults, cfgFile, secretsFile, code, ok := configPaths("config", args)
	if !ok {
		return code
	}
	cfg, err := config.Load(defaults, cfgFile, secretsFile)
	if err != nil {
		// The operator file is 0644. The client JSON may be unreadable
		// by the user who only needs PAM and ALLOWED_EMAILS.
		op, oerr := config.LoadOperator(defaults, cfgFile)
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
