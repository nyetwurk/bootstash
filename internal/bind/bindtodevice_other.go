// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !linux

package bind

import "errors"

func bindToDevice(_ int, _ string) error {
	return errors.New("SO_BINDTODEVICE unavailable")
}
