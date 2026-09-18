// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"fmt"
	"os"

	"github.com/nyet/bootstash/internal/config"
	"github.com/nyet/bootstash/internal/configcheck"
	"github.com/nyet/bootstash/internal/version"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "--version", "-version", "-V", "version":
		fmt.Println(version.Version)
		return
	case "check-config", "-t":
		os.Exit(runCheck(os.Args[2:]))
	case "provision-google":
		os.Exit(runProvision(os.Args[2:]))
	case "help", "-h", "-help", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "bootstash: unknown command %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func runCheck(args []string) int {
	defaults := config.DefaultDistPath
	cfgFile := config.DefaultConfigPath
	secretsFile := config.DefaultSecretsPath
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-defaults":
			i++
			if i >= len(args) {
				fmt.Fprintln(os.Stderr, "-defaults requires a path")
				return 2
			}
			defaults = args[i]
		case "-config":
			i++
			if i >= len(args) {
				fmt.Fprintln(os.Stderr, "-config requires a path")
				return 2
			}
			cfgFile = args[i]
		case "-secrets":
			i++
			if i >= len(args) {
				fmt.Fprintln(os.Stderr, "-secrets requires a path")
				return 2
			}
			secretsFile = args[i]
		default:
			fmt.Fprintf(os.Stderr, "bootstash check-config: unknown argument %q\n", args[i])
			return 2
		}
	}
	cfg, err := configcheck.Check(defaults, cfgFile, secretsFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "configuration ok %s\n", configcheck.Summary(cfg))
	return 0
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: bootstash <command> [options]\n")
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "commands:\n")
	fmt.Fprintf(os.Stderr, "  check-config       parse dist defaults, operator config, secrets, and BIND specs, then exit\n")
	fmt.Fprintf(os.Stderr, "  provision-google   print Google OIDC recipe and install the downloaded client JSON\n")
	fmt.Fprintf(os.Stderr, "  version            print git describe version\n")
}
