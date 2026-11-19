// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"log/syslog"
	"os"

	"go.nyet.org/bootstash/internal/config"
	"go.nyet.org/bootstash/internal/configcheck"
	"go.nyet.org/bootstash/internal/store"
	"go.nyet.org/bootstash/internal/version"
)

func main() {
	log.SetPrefix("bootstashd: ")
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	if w, err := syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, "bootstashd"); err == nil {
		log.SetOutput(io.MultiWriter(os.Stderr, w))
	}
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
	case "config":
		os.Exit(runConfig(os.Args[2:]))
	case "provision-google":
		os.Exit(runProvision(os.Args[2:]))
	case "links":
		os.Exit(runLinks(os.Args[2:]))
	case "unlink":
		os.Exit(runUnlink(os.Args[2:]))
	case "mkdir":
		os.Exit(runMkdir(os.Args[2:]))
	case "put":
		os.Exit(runPut(os.Args[2:]))
	case "help", "-h", "-help", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "bootstash: unknown command %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func runCheck(args []string) int {
	defaults, cfgFile, secretsFile, code, ok := configPaths("check-config", args)
	if !ok {
		return code
	}
	cfg, err := configcheck.Check(defaults, cfgFile, secretsFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "configuration ok %s\n", configcheck.Summary(cfg))
	if n := configcheck.Notice(cfg); n != "" {
		fmt.Fprintln(os.Stderr, "bootstash:", n)
	}
	return 0
}

func stateFlags(fs *flag.FlagSet) (defaults, cfgFile, secrets *string) {
	defaults = fs.String("defaults", config.DefaultDistPath, "dist defaults (read DATA)")
	cfgFile = fs.String("config", config.DefaultConfigPath, "operator config (read DATA)")
	secrets = fs.String("secrets", config.DefaultSecretsPath, "OIDC client secrets")
	return
}

func configPaths(name string, args []string) (defaults, cfgFile, secrets string, code int, ok bool) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	d, c, s := stateFlags(fs)
	if err := fs.Parse(args); err != nil {
		return "", "", "", 2, false
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(os.Stderr, "bootstash %s: unknown argument %q\n", name, fs.Arg(0))
		return "", "", "", 2, false
	}
	return *d, *c, *s, 0, true
}

func openState(defaults, cfgFile, secrets string) (*store.Store, error) {
	cfg, err := config.Load(defaults, cfgFile, secrets)
	if err != nil {
		return nil, err
	}
	return store.Open(cfg.Data)
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: bootstash <command> [options]\n")
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "commands:\n")
	fmt.Fprintf(os.Stderr, "  check-config       parse dist defaults, operator config, secrets, and LISTEN specs, then exit\n")
	fmt.Fprintf(os.Stderr, "  config             print the merged config (no client secret, no crypto key)\n")
	fmt.Fprintf(os.Stderr, "  provision-google   print Google OIDC recipe and install the downloaded client JSON\n")
	fmt.Fprintf(os.Stderr, "  links              list OIDC→PAM maps (needs read of $DATA/state)\n")
	fmt.Fprintf(os.Stderr, "  unlink             drop OIDC→PAM links for a Unix user (needs write to $DATA/state)\n")
	fmt.Fprintf(os.Stderr, "  mkdir              create users/<USER> (root; same directory login creates)\n")
	fmt.Fprintf(os.Stderr, "  put                copy files into your cubby, or an allowlisted address cubby (not root)\n")
	fmt.Fprintf(os.Stderr, "  version            print git describe version\n")
}
