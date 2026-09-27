// Copyright (C) 2026 Nye Liu
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build linux

package bind

import "golang.org/x/sys/unix"

func bindToDevice(fd int, device string) error {
	return unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, device)
}
