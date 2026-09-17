// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package bind

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Manager keeps HTTP/HTTPS listeners in sync with bind specs.
type Manager struct {
	Handler   http.Handler
	UnixGroup string
	TLS       func() (*tls.Certificate, error)

	mu      sync.Mutex
	current map[string]*managed
}

type managed struct {
	id      string
	specRaw string
	ln      net.Listener
	srv     *http.Server
}

// NewManager returns an empty listener set.
func NewManager(h http.Handler, unixGroup string, tlsFn func() (*tls.Certificate, error)) *Manager {
	return &Manager{
		Handler:   h,
		UnixGroup: unixGroup,
		TLS:       tlsFn,
		current:   make(map[string]*managed),
	}
}

func targetID(t Target) string {
	return t.Network + "|" + t.Address + "|" + t.Device
}

// Sync opens new targets and closes stale ones. useTLS wraps TCP listeners.
// If reload is true, a CIDR with no matching addresses or a missing interface
// keeps the previous listeners for that spec.
func (m *Manager) Sync(specs []Spec, useTLS, reload bool) error {
	wanted := make(map[string]Target)
	specOf := make(map[string]string)
	keepRaw := make(map[string]bool)
	var firstErr error

	for i := range specs {
		sp := specs[i]
		ts, err := sp.Resolve()
		if err != nil {
			if reload && (errors.Is(err, ErrNotReady) || sp.Kind == KindCIDR) {
				log.Printf("bind %s: %v (keeping previous listeners)", sp.Raw, err)
				keepRaw[sp.Raw] = true
				continue
			}
			if errors.Is(err, ErrNotReady) {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			if sp.Kind == KindCIDR {
				return err
			}
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		for _, t := range ts {
			id := targetID(t)
			wanted[id] = t
			specOf[id] = sp.Raw
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for id, mg := range m.current {
		if _, ok := wanted[id]; ok {
			continue
		}
		if keepRaw[mg.specRaw] {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = mg.srv.Shutdown(ctx)
		cancel()
		mg.ln.Close()
		delete(m.current, id)
	}

	var listenErr error
	for id, t := range wanted {
		if _, ok := m.current[id]; ok {
			m.current[id].specRaw = specOf[id]
			continue
		}
		https := useTLS && !t.Unix
		if err := m.listenAndServe(id, specOf[id], t, https); err != nil && t.Device != "" {
			fallback, ferr := EnumerateIface(t.Device, portOf(t), familyOf(t))
			if ferr != nil {
				if listenErr == nil {
					listenErr = err
				}
				continue
			}
			okListen := false
			for _, ft := range fallback {
				fid := targetID(ft)
				if _, exists := m.current[fid]; exists {
					okListen = true
					continue
				}
				if e2 := m.listenAndServe(fid, specOf[id], ft, https); e2 == nil {
					okListen = true
				}
			}
			if !okListen && listenErr == nil {
				listenErr = err
			}
			continue
		} else if err != nil {
			if listenErr == nil {
				listenErr = err
			}
		}
	}

	if len(m.current) == 0 {
		if firstErr != nil {
			return firstErr
		}
		if listenErr != nil {
			return listenErr
		}
		return errors.New("no listeners")
	}
	return nil
}

func (m *Manager) listenAndServe(id, specRaw string, t Target, https bool) error {
	ln, err := Listen(t, m.UnixGroup)
	if err != nil {
		return err
	}
	m.serve(id, specRaw, t, ln, https)
	return nil
}

func (m *Manager) serve(id, specRaw string, t Target, ln net.Listener, https bool) {
	srv := &http.Server{
		Handler:           m.Handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	if https {
		srv.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				if m.TLS == nil {
					return nil, errors.New("no certificate")
				}
				return m.TLS()
			},
		}
		ln = tls.NewListener(ln, srv.TLSConfig)
	}
	m.current[id] = &managed{id: id, specRaw: specRaw, ln: ln, srv: srv}
	go func() {
		err := srv.Serve(ln)
		if err != nil && err != http.ErrServerClosed {
			log.Printf("listener %s: %v", t.Address, err)
		}
	}()
}

// Close stops every listener.
func (m *Manager) Close(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var last error
	for id, mg := range m.current {
		if err := mg.srv.Shutdown(ctx); err != nil {
			last = err
			mg.ln.Close()
		}
		delete(m.current, id)
	}
	return last
}

// Names returns current listener ids (for tests).
func (m *Manager) Names() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.current))
	for id := range m.current {
		out = append(out, id)
	}
	return out
}

func portOf(t Target) int {
	_, p, err := net.SplitHostPort(t.Address)
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(p)
	return n
}

func familyOf(t Target) Family {
	if t.Network == "tcp4" {
		return FamilyIPv4
	}
	if t.Network == "tcp6" {
		return FamilyIPv6
	}
	return FamilyDual
}
