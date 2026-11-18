package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

const wptFeature = "OptionId.WindowsPerformanceToolkit"

func debugInstall(format string, args ...interface{}) {
	path := filepath.Join(programDataDir(), "install-debug.log")
	ensureSecureFile(path, fileReadACL(currentUserSID()))
	logLine(path, format, args...)
}

func writeTracelogAsset() error {
	sum := sha256.Sum256(tracelogData)
	actual := hex.EncodeToString(sum[:])
	if actual != tracelogSHA256 {
		return fmt.Errorf("embedded tracelog hash mismatch: %s", actual)
	}
	return writeFileSecure(installedTracelog(), tracelogData, installFileACL())
}

func processRunning(pid int) bool {
	if pid <= 0 {
		return false
	}
	out, _, _ := runCommand("tasklist.exe", "/FI", fmt.Sprintf("PID eq %d", pid), "/NH", "/FO", "CSV")
	return strings.Contains(out, fmt.Sprintf(`"%d"`, pid))
}

func processIsOurDaemon(pid int) bool {
	p := processImagePath(pid)
	return p != "" && samePath(p, installDaemonPath())
}

func stopDaemonAndWait() {
	pid := daemonPid()
	if !processIsOurDaemon(pid) {
		pid = 0
	}
	if fileOwnerTrusted(socketPath()) {
		if resp, err := sendRequest(Request{Cmd: "shutdown"}, 5*time.Second); err == nil && resp.OK {
			deadline := time.Now().Add(8 * time.Second)
			for time.Now().Before(deadline) {
				if _, err := sendRequest(Request{Cmd: "ping"}, 500*time.Millisecond); err != nil {
					break
				}
				time.Sleep(200 * time.Millisecond)
			}
		}
	}
	if pid > 0 {
		deadline := time.Now().Add(6 * time.Second)
		for time.Now().Before(deadline) && processIsOurDaemon(pid) {
			time.Sleep(100 * time.Millisecond)
		}
		if terminateIfImage(pid, installDaemonPath()) {
			time.Sleep(300 * time.Millisecond)
		}
	}
	os.Remove(pidPath())
}

func taskXML(user string) string {
	exe := installDaemonPath()
	principal := user
	if sid := currentUserSID(); sid != "" {
		principal = sid
	}
	logonType := "InteractiveToken"
	if isSystemUser(user) {
		logonType = "ServiceAccount"
	}
	return `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <SecurityDescriptor>` + xmlEscape(taskSecurityDescriptor(user)) + `</SecurityDescriptor>
    <Author>Jog-Ming</Author>
    <Description>Windows Invariants Profiler daemon</Description>
  </RegistrationInfo>
  <Principals>
    <Principal id="Author">
      <UserId>` + xmlEscape(principal) + `</UserId>
      <LogonType>` + logonType + `</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <IdleSettings>
      <Duration>PT10M</Duration>
      <WaitTimeout>PT1H</WaitTimeout>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine>
  </Settings>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>` + xmlEscape(principal) + `</UserId>
    </LogonTrigger>
  </Triggers>
  <Actions Context="Author">
    <Exec>
      <Command>` + xmlEscape(exe) + `</Command>
      <Arguments>daemon-run</Arguments>
    </Exec>
  </Actions>
</Task>`
}

func xmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;").Replace(s)
}

func writeUTF16File(path, s string) error {
	units := utf16.Encode([]rune(s))
	buf := make([]byte, 0, 2+len(units)*2)
	buf = append(buf, 0xFF, 0xFE)
	for _, u := range units {
		buf = append(buf, byte(u), byte(u>>8))
	}
	return os.WriteFile(path, buf, 0600)
}

func createTask(user string) (err error) {
	defer func() {
		if r := recover(); r != nil {
			debugInstall("createTask panic: %v\n%s", r, debug.Stack())
			deleteTask()
			err = fmt.Errorf("scheduled task setup failed: %v", r)
		}
	}()
	xmlPath := filepath.Join(adminTempDir(), "task-"+newID()+".xml")
	if err := writeUTF16File(xmlPath, taskXML(user)); err != nil {
		return fmt.Errorf("writing task definition: %w", err)
	}
	defer os.Remove(xmlPath)
	out, code, err := runCommand("schtasks.exe", "/Create", "/TN", taskName, "/XML", xmlPath, "/F")
	if err != nil || code != 0 {
		return fmt.Errorf("schtasks failed: %s %v", truncate(out, 800), err)
	}
	if err := verifyTaskSecurity(user); err != nil {
		deleteTask()
		return fmt.Errorf("verifying scheduled task: %w", err)
	}
	return nil
}

func decodeTaskFile(data []byte) string {
	var raw []uint16
	if len(data) >= 2 && data[0] == 0xFF && data[1] == 0xFE {
		raw = make([]uint16, 0, len(data)/2)
		for i := 2; i+1 < len(data); i += 2 {
			raw = append(raw, uint16(data[i])|uint16(data[i+1])<<8)
		}
	} else if len(data) > 4 && data[1] == 0 && data[3] == 0 {
		raw = make([]uint16, 0, len(data)/2)
		for i := 0; i+1 < len(data); i += 2 {
			raw = append(raw, uint16(data[i])|uint16(data[i+1])<<8)
		}
	} else {
		return string(data)
	}
	return string(utf16.Decode(raw))
}

func isSystemUser(user string) bool {
	return strings.EqualFold(user, `NT AUTHORITY\SYSTEM`) || strings.EqualFold(user, "SYSTEM")
}

func taskExists() bool {
	_, code, err := runCommand("reg.exe", "query",
		`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\`+taskName)
	if err != nil {
		return true
	}
	return code == 0
}

func deleteTask() error {
	out, code, err := runCommand("schtasks.exe", "/Delete", "/TN", taskName, "/F")
	if err != nil {
		return err
	}
	if taskExists() {
		if code != 0 {
			return fmt.Errorf("deleting the scheduled task failed: %s", truncate(out, 300))
		}
		return errors.New("the scheduled task still exists after deletion")
	}
	return nil
}

func stopLegacyDaemon() {
	pid := readPid(legacyPidPath())
	if pid > 0 && terminateIfImage(pid, filepath.Join(legacyInstallDir(), "winvard.exe")) {
		time.Sleep(300 * time.Millisecond)
	}
}

// resetDataDir empties a product data directory. If another process has pinned
// files inside, a trusted directory is renamed aside rather than failing the
// install; the renamed copy is removed on a best-effort basis.
func resetDataDir(path string) error {
	if err := removeTreeNoFollow(path); err == nil {
		return nil
	}
	if _, statErr := os.Lstat(path); os.IsNotExist(statErr) {
		return nil
	}
	for attempt := 0; attempt < 16; attempt++ {
		aside := path + ".old-" + newID()
		if rerr := os.Rename(path, aside); rerr == nil {
			removeTreeNoFollow(aside)
			return nil
		}
	}
	return fmt.Errorf("%s is in use and cannot be moved aside", path)
}

func removeDataDirQuarantines() {
	for _, base := range []string{programDataDir(), adminTempDir()} {
		parent := filepath.Dir(base)
		entries, err := os.ReadDir(parent)
		if err != nil {
			continue
		}
		prefix := filepath.Base(base) + ".old-"
		for _, entry := range entries {
			name := entry.Name()
			if !entry.IsDir() || !strings.HasPrefix(name, prefix) {
				continue
			}
			if name != filepath.Base(name) || strings.ContainsAny(name, `\/`) {
				continue
			}
			removeTreeNoFollow(filepath.Join(parent, name))
		}
	}
}

// stopOrphanTraces stops kernel tracing sessions left behind when a daemon was
// terminated without shutting them down.
func stopOrphanTraces() {
	log := trustedTracelog()
	if log == "" {
		return
	}
	out, code, err := runCommandTimeout(30*time.Second, log, "-l")
	if err != nil || code != 0 {
		return
	}
	seen := map[string]bool{}
	for _, field := range strings.Fields(out) {
		if !strings.HasPrefix(field, "winvar_") || seen[field] {
			continue
		}
		seen[field] = true
		runCommandTimeout(30*time.Second, log, "-stop", field)
	}
}

// stopDaemonsByImage finds the daemon by its verified image path instead of
// reading pid and socket files from a data directory whose ownership has not
// been established.
func stopDaemonsByImage() {
	out, _, _ := runCommand("tasklist.exe", "/FI", "IMAGENAME eq winvard.exe", "/NH", "/FO", "CSV")
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Split(line, ",")
		if len(fields) < 2 {
			continue
		}
		pid, err := strconv.Atoi(strings.Trim(fields[1], "\" \r"))
		if err != nil || pid <= 0 {
			continue
		}
		if terminateIfImage(pid, installDaemonPath()) ||
			terminateIfImage(pid, filepath.Join(legacyInstallDir(), "winvard.exe")) {
			time.Sleep(200 * time.Millisecond)
		}
	}
}

func legacyPresent() bool {
	if dirExists(legacyInstallDir()) || dirExists(legacyProgramDataDir()) {
		return true
	}
	_, code, err := runCommand("reg.exe", "query", legacyARPKey)
	return err == nil && code == 0
}

func migrateLegacyInstall() {
	if !legacyPresent() {
		return
	}
	trustedData := legacyDataDirTrusted()
	if trustedData {
		stopLegacyDaemon()
	} else {
		stopDaemonsByImage()
	}
	runCommand("reg.exe", "delete", legacyARPKey, "/f")
	if err := removeMachinePath(legacyInstallDir()); err != nil {
		fmt.Fprintln(os.Stderr, "winvar: warning: removing legacy PATH entry:", err)
	}
	if err := removeTreeNoFollow(legacyInstallDir()); err != nil {
		fmt.Fprintln(os.Stderr, "winvar: warning: removing legacy install dir:", err)
	}
	if trustedData {
		if err := removeTreeNoFollow(legacyProgramDataDir()); err != nil {
			fmt.Fprintln(os.Stderr, "winvar: warning: removing legacy data dir:", err)
		}
	}
}

const (
	arpKey       = `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\` + appName
	legacyARPKey = `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\` + legacyAppName
)

func setARPEntry() {
	values := [][2]string{
		{"DisplayName", appName},
		{"DisplayVersion", buildVersion},
		{"Publisher", "Jog-Ming"},
		{"InstallLocation", installDir()},
		{"DisplayIcon", installExePath()},
		{"UninstallString", `"` + installExePath() + `" setup uninstall`},
		{"QuietUninstallString", `"` + installExePath() + `" setup uninstall`},
	}
	for _, value := range values {
		runCommand("reg.exe", "add", arpKey, "/v", value[0], "/t", "REG_SZ", "/d", value[1], "/f")
	}
	runCommand("reg.exe", "add", arpKey, "/v", "NoModify", "/t", "REG_DWORD", "/d", "1", "/f")
	runCommand("reg.exe", "add", arpKey, "/v", "NoRepair", "/t", "REG_DWORD", "/d", "1", "/f")
}

func removeARPEntry() {
	runCommand("reg.exe", "delete", arpKey, "/f")
}

func startTask() error {
	out, code, err := runCommand("schtasks.exe", "/Run", "/TN", taskName)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("schtasks /Run failed: %s", truncate(out, 800))
	}
	return nil
}

func waitForDaemon(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if resp, err := sendRequest(Request{Cmd: "ping"}, time.Second); err == nil && resp.OK {
			return nil
		}
		time.Sleep(300 * time.Millisecond)
	}
	return fmt.Errorf("daemon did not become ready")
}

func installWPT() error {
	url := "https://go.microsoft.com/fwlink/?linkid=2338977"
	tmp := filepath.Join(adminTempDir(), fmt.Sprintf("sdksetup-%d.exe", time.Now().UnixNano()))
	fmt.Println("downloading Windows SDK bootstrapper...")
	if err := downloadFile(url, tmp); err != nil {
		return fmt.Errorf("downloading SDK bootstrapper: %w", err)
	}
	defer os.Remove(tmp)
	if err := verifyAuthenticode(tmp); err != nil {
		return fmt.Errorf("SDK bootstrapper signature: %w", err)
	}
	fmt.Println("installing Windows Performance Toolkit (about 82 MB)...")
	out, code, err := runCommandTimeout(10*time.Minute, tmp, "/features", wptFeature, "/quiet", "/norestart", "/ceip", "off")
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("SDK setup exited %d: %s", code, truncate(out, 2000))
	}
	if trustedXperf() == "" {
		return fmt.Errorf("xperf still missing after installing the Windows Performance Toolkit")
	}
	return nil
}

func setupInstall(args []string) int {
	user := flagValue(args, "--user")
	if !isAdmin() {
		if hasFlag(args, "--no-elevate") {
			fmt.Fprintln(os.Stderr, "winvar: administrator privileges are required; run from an elevated terminal")
			return 3
		}
		if user == "" {
			user = currentUser()
		}
		childArgs := []string{"setup", "install", "--elevated", "--user", user}
		if hasFlag(args, "--no-wpt") {
			childArgs = append(childArgs, "--no-wpt")
		}
		exe, _ := os.Executable()
		code := 0
		var err error
		if samePath(exe, installExePath()) {
			code, err = elevateSelf(childArgs)
		} else if imagePathStableForElevation(exe) {
			data, rerr := os.ReadFile(exe)
			if rerr != nil {
				fmt.Fprintln(os.Stderr, "winvar: cannot read the installer image:", rerr)
				return 1
			}
			sum := sha256.Sum256(data)
			childArgs = append(childArgs, "--source-sha256", hex.EncodeToString(sum[:]))
			code, err = elevateSelf(childArgs)
		} else {
			if serr := stageSourceImage(); serr != nil {
				fmt.Fprintln(os.Stderr, "winvar: cannot stage the installer image:", serr)
				return 1
			}
			defer func() {
				if stagedSourceLock != 0 {
					procCloseHandle.Call(uintptr(stagedSourceLock))
					stagedSourceLock = 0
				}
				os.Remove(stagedSourcePath)
				if stagedSourceDirLock != 0 {
					procCloseHandle.Call(uintptr(stagedSourceDirLock))
					stagedSourceDirLock = 0
				}
				if stagedSourceDir != "" {
					os.Remove(stagedSourceDir)
					stagedSourceDir = ""
				}
			}()
			childArgs = append(childArgs, "--source-temp", stagedSourcePath, "--source-sha256", stagedSourceHash)
			code, err = elevateSelfPath(stagedSourcePath, childArgs)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "winvar:", err)
			return 1
		}
		return code
	}
	if user == "" {
		user = currentUser()
	}
	if !strings.EqualFold(user, currentUser()) {
		fmt.Fprintln(os.Stderr, "winvar: --user must match the current account")
		return 3
	}
	if isSystemUser(user) && !isSystemUser(currentUser()) {
		fmt.Fprintln(os.Stderr, "winvar: refusing to register a SYSTEM task from a non-SYSTEM install")
		return 3
	}
	sanitizeProcessEnv()
	enableTakeoverPrivileges()
	if err := secureInstallDir(); err != nil {
		fmt.Fprintln(os.Stderr, "winvar: cannot secure install directory:", err)
		fmt.Fprintln(os.Stderr, "winvar: remove", installDir(), "manually from an elevated prompt, then retry")
		return 1
	}

	if dataDirTrusted() {
		stopDaemonAndWait()
	} else {
		stopDaemonsByImage()
	}
	stopOrphanTraces()
	removeDataDirQuarantines()
	// The previous layout left the data directory writable by the user. Drop it
	// wholesale so no pre-planted state, junction, or session survives the
	// upgrade; the install recreates it with the hardened ACL below. The delete
	// is handle-anchored and never follows a reparse point, so an untrusted or
	// squatted directory is removed instead of blocking the install.
	if err := resetDataDir(programDataDir()); err != nil {
		fmt.Fprintln(os.Stderr, "winvar: cannot reset data directory:", err)
		fmt.Fprintln(os.Stderr, "winvar: delete it manually from an elevated prompt, then retry")
		return 1
	}
	if err := resetDataDir(adminTempDir()); err != nil {
		fmt.Fprintln(os.Stderr, "winvar: cannot reset admin temp directory:", err)
		fmt.Fprintln(os.Stderr, "winvar: delete it manually from an elevated prompt, then retry")
		return 1
	}
	if dirExists(programDataDir()) || dirExists(adminTempDir()) {
		fmt.Fprintln(os.Stderr, "winvar: could not remove the previous data directory")
		return 1
	}
	if err := secureDataDir(user); err != nil {
		fmt.Fprintln(os.Stderr, "winvar: cannot secure data directory:", err)
		return 1
	}
	stagedCopy, err := stageVerifiedSource(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "winvar:", err)
		return 1
	}
	if stagedCopy != "" {
		defer os.Remove(stagedCopy)
	}
	migrateLegacyInstall()

	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "winvar:", err)
		return 1
	}
	source := exe
	if stagedCopy != "" {
		source = stagedCopy
	}
	if !samePath(source, installExePath()) {
		var err error
		if stagedCopy == "" && sourceImageLock != 0 {
			err = copyLockedImage(installExePath())
		} else {
			err = copyFile(source, installExePath())
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "winvar: cannot install executable:", err)
			return 1
		}
	}
	if err := writeDaemonBinary(); err != nil {
		fmt.Fprintln(os.Stderr, "winvar: cannot install daemon executable:", err)
		return 1
	}
	if err := writeTracelogAsset(); err != nil {
		fmt.Fprintln(os.Stderr, "winvar:", err)
		return 1
	}
	for _, p := range []string{installExePath(), installDaemonPath(), installedTracelog()} {
		if !fileExists(p) || !fileOwnerTrusted(p) || userCanWriteDir(p, currentUserSID()) {
			fmt.Fprintln(os.Stderr, "winvar: installed file is not administrator-owned:", p)
			return 1
		}
	}

	st := &State{}
	st.Version = buildVersion
	st.InstallDir = installDir()
	st.Tracelog = installedTracelog()

	xperf := trustedXperf()
	if xperf == "" && !hasFlag(args, "--no-wpt") {
		before, beforeOK := listProductsStrict()
		wptErr := installWPT()
		after, afterOK := listProductsStrict()
		if beforeOK && afterOK {
			if added := diffProducts(before, after); len(added) > 0 {
				st.WPTInstalledByUs = true
				st.WPTProducts = added
			}
		}
		xperf = trustedXperf()
		if wptErr != nil {
			fmt.Fprintln(os.Stderr, "winvar: warning:", wptErr)
			fmt.Fprintln(os.Stderr, "winvar: continuing without xperf; run 'winvar setup install' again to retry")
		}
	}
	st.Xperf = xperf
	st.TaskUser = user

	added, pathErr := ensureMachinePath(installDir())
	if pathErr != nil {
		fmt.Fprintln(os.Stderr, "winvar: warning:", pathErr)
	} else if added {
		st.PathAdded = true
		st.PathEntry = installDir()
	}

	if err := saveState(st); err != nil {
		fmt.Fprintln(os.Stderr, "winvar: cannot save state:", err)
		return 1
	}
	if err := secureDataDir(user); err != nil {
		debugInstall("secureDataDir(after save): %v", err)
		fmt.Fprintln(os.Stderr, "winvar: cannot secure data directory:", err)
		return 1
	}
	if err := createTask(user); err != nil {
		debugInstall("createTask: %v", err)
		fmt.Fprintln(os.Stderr, "winvar:", err)
		return 1
	}
	setARPEntry()

	daemonReady := false
	if err := startTask(); err != nil {
		debugInstall("startTask: %v", err)
		fmt.Fprintln(os.Stderr, "winvar: warning: daemon task could not be started:", err)
	} else if err := waitForDaemon(15 * time.Second); err != nil {
		debugInstall("waitForDaemon: %v", err)
		fmt.Fprintln(os.Stderr, "winvar: warning: daemon did not become ready:", err)
		fmt.Fprintln(os.Stderr, "winvar: it will start at the next logon; see", daemonLogPath())
	} else {
		daemonReady = true
	}

	fmt.Println(appName, "installed")
	fmt.Println("  install dir:", installDir())
	fmt.Println("  tracelog:   ", installedTracelog())
	if xperf == "" {
		fmt.Println("  xperf:       not installed; run 'winvar setup install' to add the Windows Performance Toolkit")
	} else {
		fmt.Println("  xperf:      ", xperf)
	}
	if daemonReady {
		fmt.Println("  daemon:      running (scheduled task", taskName+")")
	} else {
		fmt.Println("  daemon:      registered (starts at logon, or run 'winvar daemon start')")
	}
	if st.PathAdded {
		fmt.Println("  PATH:        added", installDir())
		fmt.Println("open a new terminal, then run: winvar run -- <command>")
	} else {
		fmt.Println("run: winvar run -- <command>")
	}
	return 0
}

func isSDKBundle(p Product) bool {
	return strings.Contains(strings.ToLower(p.DisplayName), "software development kit")
}

func findInstalledProduct(key string) (Product, bool) {
	for k, p := range listProducts() {
		if strings.EqualFold(k, key) {
			return p, true
		}
	}
	return Product{}, false
}

func isWPTProduct(p Product) bool {
	name := strings.ToLower(p.DisplayName)
	publisher := strings.ToLower(p.Publisher)
	if !strings.Contains(publisher, "microsoft") {
		return false
	}
	return strings.Contains(name, "software development kit") ||
		strings.Contains(name, "performance toolkit") ||
		strings.Contains(name, "windows sdk")
}

func uninstallProduct(p Product, isBundle bool) bool {
	actual, ok := findInstalledProduct(p.Key)
	if !ok {
		return true
	}
	if !isWPTProduct(actual) {
		fmt.Fprintf(os.Stderr, "warning: refusing to uninstall unexpected product %s\n", actual.DisplayName)
		return true
	}
	p = actual
	key := filepath.Base(strings.ReplaceAll(p.Key, "/", `\`))
	if strings.HasPrefix(key, "{") {
		out, code, err := runCommandTimeout(5*time.Minute, "msiexec.exe", "/x", key, "/qn", "/norestart")
		if err == nil && code == 0 {
			return true
		}
		// 1605: the product is already gone; that is a completed removal.
		if err == nil && code == 1605 && !isBundle {
			return true
		}
		fmt.Fprintf(os.Stderr, "warning: uninstalling %s failed (exit %d): %s %v\n", p.DisplayName, code, truncate(out, 300), err)
		return false
	}
	// Only MSI products can be removed automatically. Executing an EXE
	// UninstallString from the registry would give a writable HKLM subkey
	// administrator code execution.
	fmt.Fprintf(os.Stderr, "warning: skipping non-MSI uninstaller for %s\n", p.DisplayName)
	return true
}

func setupUninstall(args []string) int {
	if !isAdmin() {
		if hasFlag(args, "--no-elevate") {
			fmt.Fprintln(os.Stderr, "winvar: administrator privileges are required; run from an elevated terminal")
			return 3
		}
		childArgs := []string{"setup", "uninstall", "--elevated"}
		exe, _ := os.Executable()
		code := 0
		var err error
		if samePath(exe, installExePath()) {
			code, err = elevateSelf(childArgs)
		} else if imagePathStableForElevation(exe) {
			data, rerr := os.ReadFile(exe)
			if rerr != nil {
				fmt.Fprintln(os.Stderr, "winvar: cannot read the uninstaller image:", rerr)
				return 1
			}
			sum := sha256.Sum256(data)
			childArgs = append(childArgs, "--source-sha256", hex.EncodeToString(sum[:]))
			code, err = elevateSelf(childArgs)
		} else {
			if serr := stageSourceImage(); serr != nil {
				fmt.Fprintln(os.Stderr, "winvar: cannot stage the uninstaller image:", serr)
				return 1
			}
			defer func() {
				if stagedSourceLock != 0 {
					procCloseHandle.Call(uintptr(stagedSourceLock))
					stagedSourceLock = 0
				}
				os.Remove(stagedSourcePath)
				if stagedSourceDirLock != 0 {
					procCloseHandle.Call(uintptr(stagedSourceDirLock))
					stagedSourceDirLock = 0
				}
				if stagedSourceDir != "" {
					os.Remove(stagedSourceDir)
					stagedSourceDir = ""
				}
			}()
			childArgs = append(childArgs, "--source-temp", stagedSourcePath, "--source-sha256", stagedSourceHash)
			code, err = elevateSelfPath(stagedSourcePath, childArgs)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "winvar:", err)
			return 1
		}
		return code
	}

	sanitizeProcessEnv()
	enableTakeoverPrivileges()
	failures := 0
	// Disable the task first so the installing user cannot restart the daemon
	// between stopping it and deleting the registration.
	runCommand("schtasks.exe", "/Change", "/TN", taskName, "/DISABLE")
	stateTrusted := dataDirTrusted()
	// Remove the task before touching the data directory, so a pinned or
	// squatted directory can never keep the elevated ONLOGON task registered.
	if stateTrusted {
		stopDaemonAndWait()
		stopLegacyDaemon()
	} else {
		stopDaemonsByImage()
	}
	stopOrphanTraces()
	if err := deleteTask(); err != nil {
		fmt.Fprintln(os.Stderr, "winvar: warning:", err)
		failures++
	}
	removeARPEntry()
	runCommand("reg.exe", "delete", legacyARPKey, "/f")

	if stateTrusted {
		if err := secureDataDir(currentUser()); err != nil {
			fmt.Fprintln(os.Stderr, "winvar: cannot secure data directory:", err)
			return 1
		}
	} else {
		// Untrusted or user-writable data directories are deleted before
		// staging, so no administrator write lands in a squatted tree.
		for _, dir := range []string{programDataDir(), adminTempDir()} {
			if err := resetDataDir(dir); err != nil {
				fmt.Fprintln(os.Stderr, "winvar: warning: cannot remove untrusted directory:", err)
			}
		}
		if err := secureDataDir(currentUser()); err != nil {
			fmt.Fprintln(os.Stderr, "winvar: cannot secure data directory:", err)
			return 1
		}
	}
	stagedCopy, err := stageVerifiedSource(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "winvar:", err)
		return 1
	}
	if stagedCopy != "" {
		defer os.Remove(stagedCopy)
	}

	exe, _ := os.Executable()
	if sameDir(filepath.Dir(exe), installDir()) && !hasFlag(args, "--relocated") {
		tmp := filepath.Join(adminTempDir(), "uninstall-"+newID()+".exe")
		if err := copyFile(exe, tmp); err != nil {
			fmt.Fprintln(os.Stderr, "winvar:", err)
			return 1
		}
		cmd := exec.Command(tmp, "setup", "uninstall", "--elevated", "--relocated")
		cmd.Dir = system32("")
		cmd.Env = sanitizedEnvironment()
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Stdin = os.Stdin
		if err := cmd.Start(); err != nil {
			fmt.Fprintln(os.Stderr, "winvar:", err)
			return 1
		}
		waitErr := cmd.Wait()
		if exitErr, ok := waitErr.(*exec.ExitError); ok {
			return exitErr.ExitCode()
		}
		if waitErr != nil {
			fmt.Fprintln(os.Stderr, "winvar:", waitErr)
			return 1
		}
		return 0
	}
	if hasFlag(args, "--relocated") {
		time.Sleep(500 * time.Millisecond)
	}

	var st *State
	if stateTrusted {
		st = loadState()
	}

	if st != nil && st.PathAdded && st.PathEntry != "" {
		if err := removeMachinePath(st.PathEntry); err != nil {
			fmt.Fprintln(os.Stderr, "winvar: warning:", err)
		}
	}
	for _, dir := range []string{legacyInstallDir(), installDir()} {
		if err := removeMachinePath(dir); err != nil {
			fmt.Fprintln(os.Stderr, "winvar: warning:", err)
		}
	}
	if st != nil && st.WPTInstalledByUs && len(st.WPTProducts) > 0 {
		fmt.Println("removing Windows Performance Toolkit components installed by winvar...")
		var bundles, others []Product
		for _, p := range st.WPTProducts {
			if isSDKBundle(p) {
				bundles = append(bundles, p)
			} else {
				others = append(others, p)
			}
		}
		for _, bundle := range bundles {
			ok := uninstallProduct(bundle, true)
			if !ok {
				time.Sleep(2 * time.Second)
				ok = uninstallProduct(bundle, true)
			}
			if !ok {
				failures++
			}
		}
		remaining := listProducts()
		for _, p := range others {
			if _, still := remaining[p.Key]; !still {
				continue
			}
			if !uninstallProduct(p, false) {
				failures++
			}
		}
	}

	removeDataDirQuarantines()
	cleanupFailed := false
	for _, dir := range []string{installDir(), legacyInstallDir()} {
		if err := removeTreeNoFollow(dir); err != nil {
			fmt.Fprintln(os.Stderr, "winvar: warning: removing", dir+":", err)
			cleanupFailed = true
		}
	}
	selfInAdmin := sameDir(filepath.Dir(exe), adminTempDir())
	for _, dir := range []string{programDataDir(), adminTempDir()} {
		if selfInAdmin && dir == adminTempDir() {
			// The relocated uninstaller is running from this directory; keep
			// the directory, remove every sibling, and schedule the running
			// image for deletion at the next boot.
			scheduleDeleteOnReboot(exe)
			entries, rerr := os.ReadDir(adminTempDir())
			if rerr != nil && !os.IsNotExist(rerr) {
				fmt.Fprintln(os.Stderr, "winvar: warning: removing", dir+":", rerr)
				cleanupFailed = true
			}
			for _, entry := range entries {
				if entry.Name() == filepath.Base(exe) {
					continue
				}
				if err := removeTreeNoFollow(filepath.Join(adminTempDir(), entry.Name())); err != nil {
					fmt.Fprintln(os.Stderr, "winvar: warning: removing", filepath.Join(dir, entry.Name())+":", err)
					cleanupFailed = true
				}
			}
			continue
		}
		if err := resetDataDir(dir); err != nil {
			fmt.Fprintln(os.Stderr, "winvar: warning: removing", dir+":", err)
			cleanupFailed = true
		}
	}
	if legacyDataDirTrusted() {
		if err := removeTreeNoFollow(legacyProgramDataDir()); err != nil {
			fmt.Fprintln(os.Stderr, "winvar: warning: removing legacy data directory:", err)
			cleanupFailed = true
		}
	}

	if hasFlag(args, "--relocated") {
		scheduleDeleteOnReboot(exe)
	}
	if failures > 0 || cleanupFailed {
		if failures > 0 {
			fmt.Fprintf(os.Stderr, "winvar: warning: %d dependency component(s) could not be removed; retry after a reboot\n", failures)
		}
		fmt.Println(appName, "uninstalled")
		return 4
	}
	fmt.Println(appName, "uninstalled")
	return 0
}

type SetupStatus struct {
	Installed        bool   `json:"installed"`
	Ready            bool   `json:"ready"`
	Version          string `json:"version"`
	InstallDir       string `json:"install_dir"`
	DaemonRunning    bool   `json:"daemon_running"`
	Tracelog         string `json:"tracelog"`
	Xperf            string `json:"xperf"`
	WPTInstalledByUs bool   `json:"wpt_installed_by_us"`
	PathAdded        bool   `json:"path_added"`
	TaskUser         string `json:"task_user"`
}

func cmdSetupStatus(args []string) int {
	var st *State
	if dataDirTrusted() {
		st = loadState()
	}
	status := SetupStatus{
		Installed:  st != nil && fileExists(installExePath()),
		Version:    buildVersion,
		InstallDir: installDir(),
	}
	if st != nil {
		status.Version = st.Version
		status.WPTInstalledByUs = st.WPTInstalledByUs
		status.PathAdded = st.PathAdded
		status.TaskUser = st.TaskUser
	}
	status.Tracelog = findTracelog()
	status.Xperf = findXperf()
	if resp, err := sendRequest(Request{Cmd: "ping"}, time.Second); err == nil && resp.OK {
		status.DaemonRunning = true
	}
	status.Ready = status.Installed && status.DaemonRunning && status.Xperf != ""
	if hasFlag(args, "--json") {
		data, _ := json.MarshalIndent(status, "", "  ")
		fmt.Println(string(data))
	} else {
		fmt.Printf("installed: %v\nready: %v\nversion: %s\ninstall dir: %s\ndaemon running: %v\ntracelog: %s\nxperf: %s\nwpt installed by us: %v\npath added: %v\ntask user: %s\n",
			status.Installed, status.Ready, sanitizeOutput(status.Version), sanitizeOutput(status.InstallDir),
			status.DaemonRunning, sanitizeOutput(status.Tracelog), sanitizeOutput(status.Xperf),
			status.WPTInstalledByUs, status.PathAdded, sanitizeOutput(status.TaskUser))
	}
	if status.Ready {
		return 0
	}
	return 1
}

func cmdSetup(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: winvar setup status|install|uninstall")
		return 2
	}
	switch args[0] {
	case "status":
		return cmdSetupStatus(args[1:])
	case "install":
		return setupInstall(args[1:])
	case "uninstall":
		return setupUninstall(args[1:])
	default:
		fmt.Fprintln(os.Stderr, "usage: winvar setup status|install|uninstall")
		return 2
	}
}
