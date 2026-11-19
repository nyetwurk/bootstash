// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package config

import (
	"fmt"
	"strconv"
	"strings"
)

// Format is the merged configuration as KEY=value lines, in the same
// syntax as the operator file. Repeatable keys are one line each.
// The Google client secret and the OIDC crypto key are omitted.
// TLS and OVPN_TOKEN are the resolved values: no, or auto when on.
// PAM is always yes or no. An explicit empty IDP list is one blank
// IDP= line. Derived PUBLIC_URL, CERT_NAME, and TLS paths are included
// when set.
func (c *Config) Format() string {
	if c == nil {
		return ""
	}
	var b strings.Builder
	kv(&b, "DATA", c.Data)
	for _, spec := range c.Binds {
		kv(&b, "LISTEN", spec)
	}
	kv(&b, "PUBLIC_URL", c.PublicURL)
	kv(&b, "CERT_NAME", c.CertName)
	kvOff(&b, "TLS", c.DisableTLS, "auto")
	kv(&b, "TLS_CERT", c.TLSCert)
	kv(&b, "TLS_KEY", c.TLSKey)
	kvOff(&b, "OVPN_TOKEN", c.DisableOvpnToken, "auto")
	kvOff(&b, "PAM", !c.PAM, "yes")
	kv(&b, "PAM_SERVICE", c.PAMService)
	kv(&b, "UNIX_GROUP", c.UnixGroup)
	if c.MaxUpload > 0 {
		kv(&b, "MAX_UPLOAD", strconv.FormatInt(c.MaxUpload, 10))
	}
	if len(c.AdminUsers) > 0 {
		kv(&b, "ADMIN_USERS", strings.Join(c.AdminUsers, ","))
	}
	for _, email := range c.AllowedEmails {
		kv(&b, "ALLOWED_EMAILS", email)
	}
	providers := c.Providers()
	if c.IDPSet && len(providers) == 0 {
		fmt.Fprintf(&b, "IDP=\n")
	} else {
		for _, name := range providers {
			kv(&b, "IDP", name)
		}
	}
	kv(&b, "OIDC_GOOGLE_CLIENT_ID", c.GoogleClientID)
	return b.String()
}

func kv(b *strings.Builder, key, val string) {
	if val == "" {
		return
	}
	fmt.Fprintf(b, "%s=%s\n", key, val)
}

func kvOff(b *strings.Builder, key string, off bool, on string) {
	if off {
		kv(b, key, "no")
		return
	}
	kv(b, key, on)
}
