//go:build !daemon

package main

import (
	_ "embed"
)

//go:embed assets/winvard.exe
var daemonData []byte

const daemonBuild = false

func writeDaemonBinary() error {
	return writeFileSecure(installDaemonPath(), daemonData, installFileACL())
}
