//go:build daemon

package main

import "errors"

const daemonBuild = true

func writeDaemonBinary() error {
	return errors.New("the daemon binary cannot perform an install")
}
