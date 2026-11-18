package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type Product struct {
	Key             string `json:"key"`
	DisplayName     string `json:"display_name"`
	Publisher       string `json:"publisher"`
	UninstallString string `json:"uninstall_string"`
}

type State struct {
	Version          string    `json:"version"`
	InstallDir       string    `json:"install_dir"`
	Tracelog         string    `json:"tracelog"`
	Xperf            string    `json:"xperf"`
	WPTInstalledByUs bool      `json:"wpt_installed_by_us"`
	WPTProducts      []Product `json:"wpt_products"`
	PathAdded        bool      `json:"path_added"`
	PathEntry        string    `json:"path_entry"`
	TaskUser         string    `json:"task_user"`
}

func installDir() string     { return filepath.Join(programFilesDir(), appName) }
func programDataDir() string { return filepath.Join(programDataBaseDir(), appName) }

func legacyInstallDir() string     { return filepath.Join(programFilesDir(), legacyAppName) }
func legacyProgramDataDir() string { return filepath.Join(programDataBaseDir(), legacyAppName) }
func legacyStatePath() string      { return filepath.Join(legacyProgramDataDir(), "state.json") }
func legacyPidPath() string        { return filepath.Join(legacyProgramDataDir(), "ipc", "daemon.pid") }

func installExePath() string    { return filepath.Join(installDir(), "winvar.exe") }
func installDaemonPath() string { return filepath.Join(installDir(), "winvard.exe") }
func installedTracelog() string { return filepath.Join(installDir(), "tracelog.exe") }
func statePath() string         { return filepath.Join(programDataDir(), "state.json") }
func socketPath() string        { return filepath.Join(programDataDir(), "ipc", "winvar.sock") }
func pidPath() string           { return filepath.Join(programDataDir(), "ipc", "daemon.pid") }
func daemonLogPath() string     { return filepath.Join(programDataDir(), "logs", "winvar.log") }
func sessionsDir() string       { return filepath.Join(programDataDir(), "sessions") }

func loadStateFrom(path string) *State {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var st State
	if json.Unmarshal(data, &st) != nil {
		return nil
	}
	return &st
}

func loadState() *State { return loadStateFrom(statePath()) }

func saveState(st *State) error {
	sid := currentUserSID()
	if sid == "" {
		return fmt.Errorf("cannot determine the current user SID")
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return writeFileSecure(statePath(), data, fileReadACL(sid))
}

func findTracelog() string {
	if dataDirTrusted() {
		if st := loadState(); st != nil && fileExists(st.Tracelog) {
			return st.Tracelog
		}
	}
	if fileExists(installedTracelog()) {
		return installedTracelog()
	}
	if exe, err := os.Executable(); err == nil {
		p := filepath.Join(filepath.Dir(exe), "tracelog.exe")
		if fileExists(p) {
			return p
		}
	}
	if p, err := exec.LookPath("tracelog.exe"); err == nil {
		return p
	}
	return ""
}

func findXperf() string {
	if dataDirTrusted() {
		if st := loadState(); st != nil && fileExists(st.Xperf) {
			return st.Xperf
		}
	}
	for _, root := range []string{programFilesX86Dir(), programFilesDir()} {
		p := filepath.Join(root, "Windows Kits", "10", "Windows Performance Toolkit", "xperf.exe")
		if fileExists(p) {
			return p
		}
	}
	if p, err := exec.LookPath("xperf.exe"); err == nil {
		return p
	}
	return ""
}

func listProducts() map[string]Product {
	products := map[string]Product{}
	roots := []string{
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
		`HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`,
	}
	for _, root := range roots {
		out, _, _ := runCommand("reg.exe", "query", root, "/s")
		var current string
		for _, raw := range strings.Split(out, "\n") {
			line := strings.TrimRight(raw, "\r")
			if strings.HasPrefix(line, "HKEY_") {
				current = line
				if _, ok := products[current]; !ok {
					products[current] = Product{Key: current}
				}
				continue
			}
			if current == "" {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 3 {
				continue
			}
			value := strings.Join(fields[2:], " ")
			p := products[current]
			switch fields[0] {
			case "DisplayName":
				p.DisplayName = value
			case "Publisher":
				p.Publisher = value
			case "UninstallString":
				p.UninstallString = value
			}
			products[current] = p
		}
	}
	filtered := map[string]Product{}
	for key, p := range products {
		if p.DisplayName != "" || p.UninstallString != "" {
			filtered[key] = p
		}
	}
	return filtered
}

// listProductsStrict returns a product snapshot only when both registry roots
// were queried successfully and the result looks complete; a partial baseline
// would make every pre-existing product look newly installed.
func listProductsStrict() (map[string]Product, bool) {
	for _, root := range []string{
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
		`HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`,
	} {
		_, code, err := runCommand("reg.exe", "query", root, "/s")
		if err != nil || (code != 0 && code != 1) {
			return nil, false
		}
	}
	products := listProducts()
	if len(products) < 10 {
		return nil, false
	}
	return products, true
}

func diffProducts(before, after map[string]Product) []Product {
	var added []Product
	for key, p := range after {
		if _, ok := before[key]; !ok {
			added = append(added, p)
		}
	}
	return added
}

func psQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func machinePath() (string, error) {
	script := "[Environment]::GetEnvironmentVariable('Path','Machine')"
	out, code, err := runCommand("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	if err != nil {
		return "", err
	}
	if code != 0 {
		return "", fmt.Errorf("reading machine PATH failed: %s", truncate(out, 500))
	}
	return strings.TrimSpace(out), nil
}

func ensureMachinePath(dir string) (bool, error) {
	script := fmt.Sprintf(
		"$p=[Environment]::GetEnvironmentVariable('Path','Machine'); if ($null -eq $p) { $p='' }; "+
			"$parts=@($p -split ';' | Where-Object { $_ -ne '' }); "+
			"if ($parts -notcontains %s) { [Environment]::SetEnvironmentVariable('Path', (($parts + %s) -join ';'), 'Machine'); 'added' } else { 'present' }",
		psQuote(dir), psQuote(dir))
	out, code, err := runCommand("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	if err != nil {
		return false, err
	}
	if code != 0 {
		return false, fmt.Errorf("updating machine PATH failed: %s", truncate(out, 500))
	}
	return strings.Contains(out, "added"), nil
}

func removeMachinePath(dir string) error {
	script := fmt.Sprintf(
		"$p=[Environment]::GetEnvironmentVariable('Path','Machine'); if ($null -eq $p) { $p='' }; "+
			"$parts=@($p -split ';' | Where-Object { $_ -ne '' -and $_ -ne %s }); "+
			"[Environment]::SetEnvironmentVariable('Path', ($parts -join ';'), 'Machine')",
		psQuote(dir))
	_, code, err := runCommand("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("removing machine PATH entry failed with exit code %d", code)
	}
	return nil
}
