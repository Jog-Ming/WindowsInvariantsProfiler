package main

import (
	"fmt"
	"os"
)

const usageText = `winvar - per-process CPU performance counters on Windows

usage:
  winvar run [--json out] [--name substr] [--top N] [--keep] [--timeout S]
             [--counter C] -- <command> [args...]
  winvar parse <dump.txt> [--json out] [--name substr] [--top N]
  winvar compare <a.json> <b.json>
  winvar profiles
  winvar daemon status|start|stop|restart
  winvar setup status [--json]|install [--no-wpt]|uninstall
  winvar version

The default counter is InstructionRetired; --counter selects other PMC
counters. Each result also reports context switches and CPU time.
The daemon runs as a scheduled task with highest privileges, so measurements
do not trigger UAC after installation. The measured command itself runs as the
calling user, in the calling directory and environment.
`

func main() {
	hardenDllSearch()
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "setup" {
		if daemonBuild {
			fmt.Fprintln(os.Stderr, "winvar: the daemon binary cannot perform setup")
			os.Exit(2)
		}
		if exe, err := os.Executable(); err == nil && samePath(exe, installDaemonPath()) {
			fmt.Fprintln(os.Stderr, "winvar: setup must run from winvar.exe")
			os.Exit(2)
		}
		if err := lockSourceImage(); err != nil {
			fmt.Fprintf(os.Stderr, "winvar: cannot lock the installer image: %v\n", err)
			os.Exit(1)
		}
	}
	if len(args) == 0 {
		fmt.Print(usageText)
		return
	}
	switch args[0] {
	case "run":
		os.Exit(cmdRun(args[1:]))
	case "parse":
		os.Exit(cmdParse(args[1:]))
	case "compare":
		os.Exit(cmdCompare(args[1:]))
	case "profiles":
		os.Exit(cmdProfiles(args[1:]))
	case "daemon":
		os.Exit(cmdDaemon(args[1:]))
	case "setup":
		os.Exit(cmdSetup(args[1:]))
	case "daemon-run":
		os.Exit(daemonRun())
	case "version", "--version", "-v":
		fmt.Println("winvar", buildVersion)
	case "help", "--help", "-h":
		fmt.Print(usageText)
	default:
		fmt.Fprintf(os.Stderr, "winvar: unknown command %q\n\n", args[0])
		fmt.Fprint(os.Stderr, usageText)
		os.Exit(2)
	}
}
