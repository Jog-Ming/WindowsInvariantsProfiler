package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Request struct {
	Cmd      string   `json:"cmd"`
	ID       string   `json:"id"`
	Counters []string `json:"counters"`
	Keep     bool     `json:"keep"`
}

type RunResult struct {
	Tool     string   `json:"tool"`
	Version  string   `json:"version"`
	Command  []string `json:"command,omitempty"`
	ExitCode int      `json:"exit_code"`
	ElapsedS float64  `json:"elapsed_s"`
	Session  string   `json:"session,omitempty"`
	TraceDir string   `json:"trace_dir,omitempty"`
	*ParseResult
}

type Status struct {
	Version  string `json:"version"`
	UptimeS  int64  `json:"uptime_s"`
	Sessions int    `json:"sessions"`
	Tracelog string `json:"tracelog"`
	Xperf    string `json:"xperf"`
}

type Response struct {
	OK      bool       `json:"ok"`
	Error   string     `json:"error,omitempty"`
	Version string     `json:"version,omitempty"`
	Text    string     `json:"text,omitempty"`
	Result  *RunResult `json:"result,omitempty"`
	Status  *Status    `json:"status,omitempty"`
}

type daemonSession struct {
	ID       string
	Name     string
	Dir      string
	Raw      string
	Merged   string
	Dump     string
	Started  time.Time
	Running  bool
	Starting bool
	Stopping bool
	Overflow bool
}

type keptDir struct {
	at   time.Time
	size int64
}

type daemon struct {
	mu        sync.Mutex
	sessions  map[string]*daemonSession
	kept      map[string]keptDir
	keptBytes int64
	parseSem  chan struct{}
	starting  sync.WaitGroup
	start     time.Time
	tracelog  string
	xperf     string
	log       string
	closing   bool
}

var (
	idRe      = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	counterRe = regexp.MustCompile(`^[A-Za-z0-9_,]{1,200}$`)
)

const (
	ipcMaxLineBytes = 64 << 10
	ipcReadDeadline = 30 * time.Second
	maxConnections  = 32
	maxLiveSessions = 8
	maxSessionAge   = 30 * time.Minute
	maxKeptDirs     = 64
	maxKeptAge      = 24 * time.Hour
	maxTraceBytes   = 1 << 30
	maxKeptBytes    = 8 << 30
	maxDumpBytes    = 256 << 20
)

func commandDeadline(cmd string) time.Duration {
	switch cmd {
	case "result":
		return 40 * time.Minute
	case "start", "stop", "shutdown":
		return 6 * time.Minute
	default:
		return time.Minute
	}
}

func daemonRun() int {
	if !isAdmin() {
		fmt.Fprintln(os.Stderr, "winvar: administrator privileges are required")
		return 1
	}
	sanitizeProcessEnv()
	enableTakeoverPrivileges()
	// Only trust an already-running instance when its socket is administrator
	// owned; a pre-planted socket in a legacy user-writable data directory must
	// not be able to make this process exit.
	if dataDirTrusted() && fileOwnerTrusted(socketPath()) {
		if resp, err := sendRequest(Request{Cmd: "ping"}, 2*time.Second); err == nil && resp.OK {
			return 0
		}
	}
	if err := secureDataDir(currentUser()); err != nil {
		fmt.Fprintln(os.Stderr, "winvar: cannot secure data directory:", err)
		return 1
	}
	ipcSID := currentUserSID()
	if ipcSID == "" {
		fmt.Fprintln(os.Stderr, "winvar: cannot determine the current user SID")
		return 1
	}
	ipcDir := filepath.Join(programDataDir(), "ipc")
	// Hide the ipc directory while the socket is created. Otherwise the socket
	// is briefly owned by the invoking user inside a traversable directory,
	// and the owner's implicit WRITE_DAC would let that user add ACEs that the
	// later /grant:r does not remove.
	if err := setSecureDir(ipcDir, adminDirACL()); err != nil {
		fmt.Fprintln(os.Stderr, "winvar: cannot secure the ipc directory:", err)
		return 1
	}
	stopOrphanTraces()
	log := daemonLogPath()
	if err := ensureSecureFile(log, fileReadACL(currentUserSID())); err != nil {
		fmt.Fprintln(os.Stderr, "winvar: cannot secure the daemon log:", err)
		return 1
	}
	logLine(log, "daemon starting, version %s", buildVersion)

	if fileExists(socketPath()) {
		os.Remove(socketPath())
	}
	ln, err := net.Listen("unix", socketPath())
	if err != nil {
		logLine(log, "listen failed: %v", err)
		return 1
	}
	if err := secureSocket(currentUser()); err != nil {
		ln.Close()
		os.Remove(socketPath())
		logLine(log, "secureSocket failed: %v", err)
		return 1
	}
	if err := writeFileSecure(pidPath(), []byte(strconv.Itoa(os.Getpid())),
		fileReadACL(ipcSID)); err != nil {
		logLine(log, "cannot write pid file: %v", err)
	}
	if err := verifySocketACL(currentUser()); err != nil {
		ln.Close()
		os.Remove(socketPath())
		os.Remove(pidPath())
		logLine(log, "socket ACL verification failed: %v", err)
		return 1
	}
	if err := setSecureDir(ipcDir, ipcDirACL(ipcSID)); err != nil {
		ln.Close()
		os.Remove(socketPath())
		os.Remove(pidPath())
		logLine(log, "restoring the ipc directory ACL failed: %v", err)
		return 1
	}
	defer func() {
		ln.Close()
		os.Remove(socketPath())
		os.Remove(pidPath())
		logLine(log, "daemon stopped")
	}()

	d := &daemon{
		sessions: map[string]*daemonSession{},
		kept:     map[string]keptDir{},
		parseSem: make(chan struct{}, 1),
		start:    time.Now(),
		tracelog: trustedTracelog(),
		xperf:    trustedXperf(),
		log:      log,
	}
	if d.tracelog == "" {
		logLine(log, "warning: trusted tracelog.exe not found")
	}
	if d.xperf == "" {
		logLine(log, "warning: trusted xperf.exe not found")
	}
	d.seedKept()
	go d.cleanupLoop()
	logLine(log, "daemon ready on %s", socketPath())

	sem := make(chan struct{}, maxConnections)
	for {
		conn, err := ln.Accept()
		if err != nil {
			logLine(log, "accept failed: %v", err)
			return 1
		}
		select {
		case sem <- struct{}{}:
			go func() {
				defer func() { <-sem }()
				d.handle(conn)
			}()
		default:
			writeResponse(conn, Response{Error: "too many concurrent connections"})
			conn.Close()
		}
	}
}

func (d *daemon) handle(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(ipcReadDeadline))
	reader := bufio.NewReaderSize(io.LimitReader(conn, ipcMaxLineBytes+1), ipcMaxLineBytes)
	line, err := reader.ReadBytes('\n')
	if len(line) > ipcMaxLineBytes {
		writeResponse(conn, Response{Error: "request too large"})
		return
	}
	if err != nil && len(line) == 0 {
		return
	}
	var req Request
	if err := json.Unmarshal(line, &req); err != nil {
		writeResponse(conn, Response{Error: "invalid request: " + err.Error()})
		return
	}
	conn.SetDeadline(time.Now().Add(commandDeadline(req.Cmd)))
	resp := d.dispatch(req)
	writeResponse(conn, resp)
}

func writeResponse(conn net.Conn, resp Response) {
	data, err := json.Marshal(resp)
	if err != nil {
		return
	}
	conn.Write(append(data, '\n'))
}

func (d *daemon) dispatch(req Request) Response {
	switch req.Cmd {
	case "ping":
		return Response{OK: true, Version: buildVersion}
	case "status":
		d.mu.Lock()
		defer d.mu.Unlock()
		return Response{OK: true, Status: &Status{
			Version:  buildVersion,
			UptimeS:  int64(time.Since(d.start).Seconds()),
			Sessions: len(d.sessions),
			Tracelog: d.tracelog,
			Xperf:    d.xperf,
		}}
	case "profiles":
		if d.tracelog == "" {
			return Response{Error: "tracelog.exe not found"}
		}
		out, code, err := runCommandTimeout(30*time.Second, d.tracelog, "-profilesources", "Help")
		if err != nil {
			return Response{Error: err.Error()}
		}
		if code != 0 {
			return Response{Error: fmt.Sprintf("tracelog exited %d: %s", code, truncate(out, 1000))}
		}
		return Response{OK: true, Text: out}
	case "start":
		return d.startSession(req)
	case "stop":
		return d.stopSession(req.ID)
	case "result":
		return d.result(req.ID, req.Keep)
	case "cancel":
		return d.cancel(req.ID)
	case "shutdown":
		d.shutdown()
		return Response{OK: true}
	default:
		return Response{Error: "unknown command: " + req.Cmd}
	}
}

func (d *daemon) startSession(req Request) Response {
	if !idRe.MatchString(req.ID) {
		return Response{Error: "invalid session id"}
	}
	if d.tracelog == "" {
		return Response{Error: "tracelog.exe not found; reinstall the profiler"}
	}
	if d.xperf == "" {
		return Response{Error: "xperf.exe not found; run 'winvar setup install' to add the Windows Performance Toolkit"}
	}
	counters := "InstructionRetired"
	if len(req.Counters) > 0 {
		counters = strings.Join(req.Counters, ",")
	}
	if !counterRe.MatchString(counters) {
		return Response{Error: "invalid counter list"}
	}

	d.mu.Lock()
	if d.closing {
		d.mu.Unlock()
		return Response{Error: "daemon is shutting down"}
	}
	if len(d.sessions) >= maxLiveSessions {
		d.mu.Unlock()
		return Response{Error: "too many active sessions"}
	}
	if _, exists := d.sessions[req.ID]; exists {
		d.mu.Unlock()
		return Response{Error: "session already exists"}
	}
	session := &daemonSession{ID: req.ID, Started: time.Now(), Starting: true}
	d.sessions[req.ID] = session
	d.starting.Add(1)
	d.mu.Unlock()
	defer d.starting.Done()

	dir, resp := d.beginSession(session, counters)
	if !resp.OK {
		d.mu.Lock()
		delete(d.sessions, req.ID)
		d.mu.Unlock()
		if dir != "" {
			removeTreeNoFollow(dir)
		}
		return resp
	}
	return Response{OK: true}
}

func (d *daemon) beginSession(s *daemonSession, counters string) (string, Response) {
	dir := filepath.Join(sessionsDir(), newID())
	// The session directory stays administrator-only while tracing and
	// parsing: the trace files are created under the invoking user's identity
	// and would otherwise be writable through the owner's implicit WRITE_DAC.
	if err := createSecureDir(dir, adminDirACL()); err != nil {
		return "", Response{Error: err.Error()}
	}
	sessionName := "winvar_" + s.ID
	raw := filepath.Join(dir, "raw.etl")
	out, code, err := runCommandTimeout(5*time.Minute, d.tracelog, "-start", sessionName, "-f", raw,
		"-eflag", "CSWITCH+PROC_THREAD+LOADER", "-PMC", counters+":CSWITCH")
	if err != nil {
		return dir, Response{Error: err.Error()}
	}
	if code != 0 {
		return dir, Response{Error: fmt.Sprintf("tracelog failed (exit %d): %s", code, truncate(out, 2000))}
	}
	d.mu.Lock()
	if d.closing {
		d.mu.Unlock()
		d.stopTrace(&daemonSession{Name: sessionName})
		return dir, Response{Error: "daemon is shutting down"}
	}
	s.Name = sessionName
	s.Dir = dir
	s.Raw = raw
	s.Merged = filepath.Join(dir, "merged.etl")
	s.Dump = filepath.Join(dir, "dump.txt")
	s.Running = true
	s.Starting = false
	d.mu.Unlock()
	go d.watchTrace(s)
	logLine(d.log, "session %s started (%s)", s.ID, counters)
	return "", Response{OK: true}
}

func (d *daemon) watchTrace(s *daemonSession) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for range ticker.C {
		d.mu.Lock()
		if d.closing || !s.Running || s.Stopping || s.Overflow {
			d.mu.Unlock()
			return
		}
		over := false
		if st, err := os.Stat(s.Raw); err == nil && st.Size() > maxTraceBytes {
			over = true
			s.Overflow = true
			s.Stopping = true
		}
		d.mu.Unlock()
		if !over {
			continue
		}
		resp := d.stopTrace(s)
		d.mu.Lock()
		s.Stopping = false
		if resp.OK {
			s.Running = false
		}
		d.mu.Unlock()
		return
	}
}

func (d *daemon) stopSession(id string) Response {
	d.mu.Lock()
	s, ok := d.sessions[id]
	if !ok {
		d.mu.Unlock()
		return Response{Error: "unknown session"}
	}
	if s.Starting {
		d.mu.Unlock()
		return Response{Error: "session is starting"}
	}
	if !s.Running || s.Stopping {
		d.mu.Unlock()
		return Response{OK: true}
	}
	s.Stopping = true
	d.mu.Unlock()

	resp := d.stopTrace(s)

	d.mu.Lock()
	s.Stopping = false
	if resp.OK {
		s.Running = false
	}
	d.mu.Unlock()
	return resp
}

func (d *daemon) stopTrace(s *daemonSession) Response {
	out, code, err := runCommandTimeout(5*time.Minute, d.xperf, "-stop", s.Name)
	if err != nil {
		return Response{Error: err.Error()}
	}
	if code != 0 {
		alt, altCode, _ := runCommandTimeout(5*time.Minute, d.tracelog, "-stop", s.Name)
		if altCode != 0 {
			return Response{Error: fmt.Sprintf("stopping trace failed: %s %s", truncate(out, 500), truncate(alt, 500))}
		}
	}
	logLine(d.log, "session %s stopped", s.ID)
	return Response{OK: true}
}

func (d *daemon) result(id string, keep bool) Response {
	d.mu.Lock()
	s, ok := d.sessions[id]
	if !ok {
		d.mu.Unlock()
		return Response{Error: "unknown session"}
	}
	if s.Starting {
		d.mu.Unlock()
		return Response{Error: "session is starting"}
	}
	if s.Stopping {
		d.mu.Unlock()
		return Response{Error: "session is stopping"}
	}
	if s.Running {
		s.Stopping = true
		d.mu.Unlock()
		resp := d.stopTrace(s)
		d.mu.Lock()
		s.Stopping = false
		if !resp.OK {
			d.mu.Unlock()
			return resp
		}
		s.Running = false
	}
	overflow := s.Overflow
	dir, raw, merged, dump := s.Dir, s.Raw, s.Merged, s.Dump
	delete(d.sessions, id)
	d.mu.Unlock()
	success := false
	defer func() {
		if !success {
			removeTreeNoFollow(dir)
		}
	}()

	if overflow {
		return Response{Error: "trace exceeded the 1 GiB limit; measure a shorter command"}
	}
	if !fileExists(raw) {
		return Response{Error: "no trace was recorded"}
	}
	if st, err := os.Stat(raw); err == nil && st.Size() > maxTraceBytes {
		return Response{Error: "trace exceeded the 1 GiB limit; measure a shorter command"}
	}
	select {
	case d.parseSem <- struct{}{}:
		defer func() { <-d.parseSem }()
	case <-time.After(2 * time.Minute):
		return Response{Error: "too many concurrent result parsings"}
	}
	if _, _, err := runCommandWatched(10*time.Minute, merged, maxTraceBytes, d.xperf,
		"-merge", raw, merged, "-compress"); err != nil {
		return Response{Error: err.Error()}
	}
	if !fileExists(merged) {
		return Response{Error: "xperf merge produced no output"}
	}
	out, code, err := runCommandWatched(10*time.Minute, dump, maxDumpBytes, d.xperf, "-i", merged, "-o", dump)
	if err != nil {
		return Response{Error: err.Error()}
	}
	if !fileExists(dump) {
		return Response{Error: fmt.Sprintf("xperf dump failed (exit %d): %s", code, truncate(out, 1000))}
	}
	parsed, err := parseDump(dump)
	if err != nil {
		return Response{Error: err.Error()}
	}

	result := &RunResult{
		Tool:        "winvar",
		Version:     buildVersion,
		Session:     id,
		ParseResult: parsed,
	}
	if keep {
		if err := secureTraceTree(dir, currentUser()); err != nil {
			return Response{Error: err.Error()}
		}
		if !d.keepDir(dir) {
			return Response{Error: "kept trace quota is exhausted by directories in use; close trace files and retry"}
		}
		result.TraceDir = dir
		success = true
	} else {
		removeTreeNoFollow(dir)
		success = true
	}
	logLine(d.log, "session %s parsed (%d processes)", id, len(parsed.Processes))
	return Response{OK: true, Result: result}
}

func (d *daemon) cancel(id string) Response {
	d.mu.Lock()
	s, ok := d.sessions[id]
	if !ok {
		d.mu.Unlock()
		return Response{OK: true}
	}
	if s.Starting {
		d.mu.Unlock()
		return Response{Error: "session is starting"}
	}
	if s.Stopping {
		d.mu.Unlock()
		return Response{Error: "session is stopping"}
	}
	if s.Running {
		s.Stopping = true
		d.mu.Unlock()
		resp := d.stopTrace(s)
		d.mu.Lock()
		s.Stopping = false
		if !resp.OK {
			d.mu.Unlock()
			return resp
		}
		s.Running = false
	}
	dir := s.Dir
	delete(d.sessions, id)
	d.mu.Unlock()
	removeTreeNoFollow(dir)
	return Response{OK: true}
}

func (d *daemon) shutdown() {
	type snapshot struct {
		name    string
		dir     string
		running bool
	}
	d.mu.Lock()
	d.closing = true
	var sessions []snapshot
	for _, s := range d.sessions {
		if s.Starting {
			continue
		}
		sessions = append(sessions, snapshot{name: s.Name, dir: s.Dir, running: s.Running && !s.Stopping})
	}
	d.sessions = map[string]*daemonSession{}
	d.mu.Unlock()
	for _, s := range sessions {
		if s.running {
			d.stopTrace(&daemonSession{Name: s.name})
		}
		if s.dir != "" {
			removeTreeNoFollow(s.dir)
		}
	}
	os.Remove(socketPath())
	os.Remove(pidPath())
	logLine(d.log, "shutdown requested")
	go func() {
		d.starting.Wait()
		time.Sleep(200 * time.Millisecond)
		os.Exit(0)
	}()
}

// dropKept removes a kept directory and only then releases its quota. A
// directory whose files are held open stays accounted for, so the quota cannot
// be bypassed by pinning handles.
func (d *daemon) dropKept(dir string) bool {
	d.mu.Lock()
	kept, ok := d.kept[dir]
	if ok {
		delete(d.kept, dir)
	}
	d.mu.Unlock()
	if !ok {
		return true
	}
	if err := removeTreeNoFollow(dir); err != nil {
		d.mu.Lock()
		if _, exists := d.kept[dir]; !exists {
			d.kept[dir] = kept
		}
		d.mu.Unlock()
		logLine(d.log, "cannot remove kept trace %s: %v", dir, err)
		return false
	}
	d.mu.Lock()
	d.keptBytes -= kept.size
	d.mu.Unlock()
	return true
}

// enforceKept evicts oldest kept traces until the count and byte limits hold.
// It stops once the oldest remaining directory cannot be removed.
func (d *daemon) enforceKept() {
	for {
		d.mu.Lock()
		if len(d.kept) <= maxKeptDirs && d.keptBytes <= maxKeptBytes {
			d.mu.Unlock()
			return
		}
		oldest := ""
		var oldestAt time.Time
		for k, v := range d.kept {
			if oldest == "" || v.at.Before(oldestAt) {
				oldest, oldestAt = k, v.at
			}
		}
		d.mu.Unlock()
		if oldest == "" || !d.dropKept(oldest) {
			return
		}
	}
}

func (d *daemon) keepDir(dir string) bool {
	size := dirSize(dir)
	d.mu.Lock()
	d.kept[dir] = keptDir{at: time.Now(), size: size}
	d.keptBytes += size
	d.mu.Unlock()
	d.enforceKept()
	d.mu.Lock()
	over := len(d.kept) > maxKeptDirs || d.keptBytes > maxKeptBytes
	d.mu.Unlock()
	if over {
		d.dropKept(dir)
		return false
	}
	if _, err := os.Stat(dir); err != nil {
		return false
	}
	return true
}

// seedKept accounts for directories left by a previous daemon instance so a
// restart cannot reset the quota.
func (d *daemon) seedKept() {
	entries, err := os.ReadDir(sessionsDir())
	if err != nil {
		return
	}
	var stale []string
	d.mu.Lock()
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		dir := filepath.Join(sessionsDir(), entry.Name())
		size := dirSize(dir)
		d.kept[dir] = keptDir{at: info.ModTime(), size: size}
		d.keptBytes += size
		if time.Since(info.ModTime()) > maxKeptAge {
			stale = append(stale, dir)
		}
	}
	d.mu.Unlock()
	// Expired directories stay in the ledger until removal actually succeeds;
	// a pinned directory therefore keeps consuming quota.
	for _, dir := range stale {
		d.dropKept(dir)
	}
	d.enforceKept()
}

func (d *daemon) cleanupLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		d.mu.Lock()
		var expired []*daemonSession
		var overflowing []*daemonSession
		for id, s := range d.sessions {
			if time.Since(s.Started) > maxSessionAge && !s.Stopping && !s.Starting {
				delete(d.sessions, id)
				expired = append(expired, s)
				continue
			}
			if s.Running && !s.Stopping && !s.Starting && fileExists(s.Raw) {
				if st, err := os.Stat(s.Raw); err == nil && st.Size() > maxTraceBytes {
					s.Overflow = true
					s.Stopping = true
					overflowing = append(overflowing, s)
				}
			}
		}
		var removeKept []string
		for dir, kept := range d.kept {
			if time.Since(kept.at) > maxKeptAge {
				removeKept = append(removeKept, dir)
			}
		}
		d.mu.Unlock()

		for _, s := range overflowing {
			resp := d.stopTrace(s)
			d.mu.Lock()
			s.Stopping = false
			if resp.OK {
				s.Running = false
			}
			d.mu.Unlock()
		}
		for _, s := range expired {
			if s.Running {
				d.stopTrace(s)
			}
			if s.Dir != "" {
				removeTreeNoFollow(s.Dir)
			}
		}
		for _, dir := range removeKept {
			d.dropKept(dir)
		}
		d.enforceKept()
	}
}

func dirSize(root string) int64 {
	var total int64
	filepath.WalkDir(root, func(p string, entry fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		if info, err := entry.Info(); err == nil {
			total += info.Size()
		}
		return nil
	})
	return total
}

func sendRequest(req Request, timeout time.Duration) (*Response, error) {
	if !dataDirTrusted() || !fileOwnerTrusted(socketPath()) {
		return nil, errors.New("the daemon socket is not trusted")
	}
	conn, err := net.DialTimeout("unix", socketPath(), 2*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return nil, err
	}
	var resp Response
	if err := json.NewDecoder(io.LimitReader(conn, 1<<20)).Decode(&resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func readPid(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	buf := make([]byte, 64)
	n, _ := f.Read(buf)
	if n <= 0 {
		return 0
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(buf[:n])))
	return pid
}

func daemonPid() int { return readPid(pidPath()) }
