// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nyet/bootstash/internal/bind"
	"github.com/nyet/bootstash/internal/config"
	"github.com/nyet/bootstash/internal/configcheck"
	"github.com/nyet/bootstash/internal/oidcgoogle"
	"github.com/nyet/bootstash/internal/pamauth"
	"github.com/nyet/bootstash/internal/store"
	"github.com/nyet/bootstash/internal/version"
	"github.com/nyet/bootstash/internal/web"
)

func main() {
	configureLog()
	syscall.Umask(0o007)

	defaultsPath := flag.String("defaults", config.DefaultDistPath, "dist defaults file")
	configPath := flag.String("config", config.DefaultConfigPath, "operator config file")
	secretsPath := flag.String("secrets", config.DefaultSecretsPath, "OIDC client secrets file")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.BoolVar(showVersion, "V", false, "print version and exit")
	check := flag.Bool("t", false, "check configuration and exit")
	flag.BoolVar(check, "check-config", false, "check configuration and exit")
	pamHelper := flag.String("pam-helper", pamauth.DefaultHelperPath, "setuid PAM helper")
	flag.Parse()
	if *showVersion {
		fmt.Println(version.Version)
		return
	}

	cfg, err := configcheck.Check(*defaultsPath, *configPath, *secretsPath)
	if err != nil {
		log.Fatal(err)
	}
	if *check {
		fmt.Fprintf(os.Stderr, "configuration ok %s\n", configcheck.Summary(cfg))
		return
	}

	st, err := store.Open(cfg.Data)
	if err != nil {
		log.Fatal(err)
	}
	key, err := st.EnsureCryptoKey(cfg.CryptoKey)
	if err != nil {
		log.Fatal(err)
	}
	idp := &oidcgoogle.Provider{
		ClientID:     cfg.GoogleClientID,
		ClientSecret: cfg.GoogleClientSecret,
	}
	srv, err := web.New(cfg, st, idp, pamauth.New(cfg.PAMService, *pamHelper), key)
	if err != nil {
		log.Fatal(err)
	}
	if cfg.UseTLS() {
		if err := srv.LoadCertificate(cfg.TLSCert, cfg.TLSKey); err != nil {
			log.Fatal(err)
		}
	}
	if err := srv.SyncBinds(false); err != nil {
		if err != bind.ErrNotReady {
			log.Fatal(err)
		}
		log.Printf("waiting for interface: %v", err)
	}

	log.Printf("%s %s", version.Version, configcheck.Summary(cfg))
	sdNotify("READY=1")

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)

	go retryBinds(ctx, srv)

	for {
		select {
		case <-ctx.Done():
			sdNotify("STOPPING=1")
			c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			_ = srv.Close(c)
			cancel()
			return
		case <-hup:
			reload(srv, *defaultsPath, *configPath, *secretsPath)
		}
	}
}

func configureLog() {
	log.SetPrefix("bootstashd: ")
	if os.Getenv("INVOCATION_ID") != "" || os.Getenv("JOURNAL_STREAM") != "" {
		log.SetFlags(log.Lmsgprefix)
		return
	}
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
}

func retryBinds(ctx context.Context, srv *web.Server) {
	delay := time.Second
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
			err := srv.SyncBinds(false)
			if err == nil {
				return
			}
			if delay < 30*time.Second {
				delay *= 2
			}
			if delay > 30*time.Second {
				delay = 30 * time.Second
			}
		}
	}
}

func reload(srv *web.Server, defaultsPath, configPath, secretsPath string) {
	cfg, err := configcheck.Check(defaultsPath, configPath, secretsPath)
	if err != nil {
		log.Printf("reload: keeping last good config: %v", err)
		return
	}
	if cfg.UseTLS() {
		if err := srv.LoadCertificate(cfg.TLSCert, cfg.TLSKey); err != nil {
			log.Printf("reload: keeping previous certificate: %v", err)
		}
	}
	srv.SetConfig(cfg)
	if err := srv.SyncBinds(true); err != nil {
		log.Printf("reload binds: %v", err)
	} else {
		log.Printf("reloaded %s", configcheck.Summary(cfg))
	}
}
