// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

package pamauth

import "os"

// New returns Helper when helperPath is an executable, else in-process PAM.
// helperPath empty means DefaultHelperPath. In-process PAM is compiled in
// only for cgo on Linux (without -tags nopam). Otherwise New returns an
// authenticator that refuses every password.
func New(service, helperPath string) Authenticator {
	if helperPath == "" {
		helperPath = DefaultHelperPath
	}
	if st, err := os.Stat(helperPath); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
		return Helper{Path: helperPath, Service: service}
	}
	return inProcess(service)
}
