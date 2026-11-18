package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type runOptions struct {
	JSON     string
	Name     string
	Top      int
	Keep     bool
	Timeout  int
	Counters []string
	Command  []string
}

func newID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(b)
}

func parseRunOptions(args []string) (*runOptions, error) {
	opts := &runOptions{Top: 20}
	i := 0
	for i < len(args) {
		a := args[i]
		if a == "--" {
			opts.Command = args[i+1:]
			break
		}
		switch a {
		case "--json":
			i++
			if i >= len(args) {
				return nil, fmt.Errorf("--json needs a path")
			}
			opts.JSON = args[i]
		case "--name":
			i++
			if i >= len(args) {
				return nil, fmt.Errorf("--name needs a value")
			}
			opts.Name = args[i]
		case "--top":
			i++
			if i >= len(args) {
				return nil, fmt.Errorf("--top needs a number")
			}
			n, err := strconv.Atoi(args[i])
			if err != nil {
				return nil, fmt.Errorf("invalid --top value")
			}
			opts.Top = n
		case "--timeout":
			i++
			if i >= len(args) {
				return nil, fmt.Errorf("--timeout needs seconds")
			}
			n, err := strconv.Atoi(args[i])
			if err != nil {
				return nil, fmt.Errorf("invalid --timeout value")
			}
			opts.Timeout = n
		case "--counter":
			i++
			if i >= len(args) {
				return nil, fmt.Errorf("--counter needs a name")
			}
			opts.Counters = append(opts.Counters, args[i])
		case "--keep":
			opts.Keep = true
		default:
			if strings.HasPrefix(a, "-") {
				return nil, fmt.Errorf("unknown option: %s", a)
			}
			opts.Command = args[i:]
			i = len(args)
			continue
		}
		i++
	}
	if len(opts.Command) == 0 {
		return nil, fmt.Errorf("missing command; use: winvar run -- <command> [args...]")
	}
	return opts, nil
}

func ensureDaemon() error {
	if resp, err := sendRequest(Request{Cmd: "ping"}, 2*time.Second); err == nil && resp.OK {
		return nil
	}
	runCommand("schtasks.exe", "/Run", "/TN", taskName)
	deadline := time.Now().Add(12 * time.Second)
	for time.Now().Before(deadline) {
		if resp, err := sendRequest(Request{Cmd: "ping"}, time.Second); err == nil && resp.OK {
			return nil
		}
		time.Sleep(300 * time.Millisecond)
	}
	return fmt.Errorf("daemon is not running; run 'winvar daemon start' or 'winvar setup install'")
}

func killTree(pid int) {
	runCommand("taskkill.exe", "/T", "/F", "/PID", strconv.Itoa(pid))
}

func runProcess(command []string, timeout int) (int, float64) {
	cmd := exec.Command(command[0], command[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: false}
	started := time.Now()
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "winvar: cannot start %s: %v\n", command[0], err)
		return 127, 0
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var runErr error
	if timeout > 0 {
		select {
		case runErr = <-done:
		case <-time.After(time.Duration(timeout) * time.Second):
			fmt.Fprintf(os.Stderr, "winvar: command exceeded %d s, killing it\n", timeout)
			killTree(cmd.Process.Pid)
			runErr = <-done
		}
	} else {
		runErr = <-done
	}
	elapsed := time.Since(started).Seconds()
	code := 0
	if runErr != nil {
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			code = exitErr.ExitCode()
		} else {
			fmt.Fprintf(os.Stderr, "winvar: %v\n", runErr)
			code = -1
		}
	}
	return code, elapsed
}

func cmdRun(args []string) int {
	opts, err := parseRunOptions(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "winvar:", err)
		return 2
	}
	if err := ensureDaemon(); err != nil {
		fmt.Fprintln(os.Stderr, "winvar:", err)
		return 1
	}
	id := newID()
	startResp, err := sendRequest(Request{Cmd: "start", ID: id, Counters: opts.Counters}, 30*time.Second)
	if err != nil {
		fmt.Fprintln(os.Stderr, "winvar: cannot reach daemon:", err)
		return 1
	}
	if !startResp.OK {
		fmt.Fprintln(os.Stderr, "winvar:", sanitizeOutput(startResp.Error))
		return 1
	}

	exitCode, elapsed := runProcess(opts.Command, opts.Timeout)

	if resp, err := sendRequest(Request{Cmd: "stop", ID: id}, 60*time.Second); err != nil || !resp.OK {
		if err != nil {
			fmt.Fprintln(os.Stderr, "winvar: stopping trace failed:", err)
		} else {
			fmt.Fprintln(os.Stderr, "winvar:", sanitizeOutput(resp.Error))
		}
		sendRequest(Request{Cmd: "cancel", ID: id}, 30*time.Second)
		return 1
	}

	resultResp, err := sendRequest(Request{Cmd: "result", ID: id, Keep: opts.Keep}, 30*time.Minute)
	if err != nil {
		fmt.Fprintln(os.Stderr, "winvar: reading result failed:", err)
		sendRequest(Request{Cmd: "cancel", ID: id}, 30*time.Second)
		return 1
	}
	if !resultResp.OK {
		fmt.Fprintln(os.Stderr, "winvar:", sanitizeOutput(resultResp.Error))
		return 1
	}
	result := resultResp.Result
	if result == nil || result.ParseResult == nil {
		fmt.Fprintln(os.Stderr, "winvar: daemon returned no result")
		return 1
	}
	result.Command = opts.Command
	result.ExitCode = exitCode
	result.ElapsedS = elapsed
	printParseResult(result.ParseResult, opts.Name, opts.Top)
	fmt.Printf("exit code: %d   elapsed: %.2f s\n", exitCode, elapsed)
	if result.TraceDir != "" {
		fmt.Printf("trace dir: %s\n", sanitizeOutput(result.TraceDir))
	}
	if opts.JSON != "" {
		if err := writeJSON(opts.JSON, result); err != nil {
			fmt.Fprintln(os.Stderr, "winvar: writing json failed:", err)
		} else {
			fmt.Printf("json: %s\n", opts.JSON)
		}
	}
	return exitCode
}

func writeJSON(path string, value interface{}) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func cmdParse(args []string) int {
	var path, jsonOut, name string
	top := 20
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--json":
			i++
			if i < len(args) {
				jsonOut = args[i]
			}
		case "--name":
			i++
			if i < len(args) {
				name = args[i]
			}
		case "--top":
			i++
			if i < len(args) {
				top, _ = strconv.Atoi(args[i])
			}
		default:
			path = args[i]
		}
	}
	if path == "" {
		fmt.Fprintln(os.Stderr, "usage: winvar parse <dump.txt> [--json out] [--name substr] [--top N]")
		return 2
	}
	result, err := parseDump(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "winvar:", err)
		return 1
	}
	printParseResult(result, name, top)
	if jsonOut != "" {
		if err := writeJSON(jsonOut, result); err != nil {
			fmt.Fprintln(os.Stderr, "winvar:", err)
			return 1
		}
		fmt.Printf("json: %s\n", jsonOut)
	}
	return 0
}

type savedResult struct {
	Counter     string             `json:"counter"`
	ByExe       map[string][]int64 `json:"by_exe"`
	SystemTotal int64              `json:"system_total"`
}

func loadSaved(path string) (*savedResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r savedResult
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	if r.ByExe == nil {
		r.ByExe = map[string][]int64{}
	}
	return &r, nil
}

func firstValue(values []int64) int64 {
	if len(values) > 0 {
		return values[0]
	}
	return 0
}

func cmdCompare(args []string) int {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: winvar compare <a.json> <b.json>")
		return 2
	}
	a, err := loadSaved(args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, "winvar:", err)
		return 1
	}
	b, err := loadSaved(args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "winvar:", err)
		return 1
	}
	if a.Counter != b.Counter {
		fmt.Fprintf(os.Stderr, "winvar: warning: counters differ (%s vs %s)\n",
			sanitizeProcessName(a.Counter), sanitizeProcessName(b.Counter))
	}
	seen := map[string]bool{}
	var names []string
	for name := range a.ByExe {
		if !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	for name := range b.ByExe {
		if !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	sort.Slice(names, func(i, j int) bool {
		return firstValue(a.ByExe[names[i]]) > firstValue(a.ByExe[names[j]])
	})
	header := fmt.Sprintf("%-28s %18s %18s %18s %10s", "exe", "a", "b", "delta", "pct")
	fmt.Println(header)
	fmt.Println(strings.Repeat("-", len(header)))
	for _, name := range names {
		av := firstValue(a.ByExe[name])
		bv := firstValue(b.ByExe[name])
		delta := bv - av
		pct := ""
		if av != 0 {
			pct = fmt.Sprintf("%+.2f%%", float64(delta)*100/float64(av))
		}
		name = sanitizeProcessName(name)
		fmt.Printf("%-28s %18s %18s %18s %10s\n", name, comma(av), comma(bv), comma(delta), pct)
	}
	fmt.Println()
	fmt.Printf("system total: a=%s  b=%s  delta=%s\n",
		comma(a.SystemTotal), comma(b.SystemTotal), comma(b.SystemTotal-a.SystemTotal))
	return 0
}

func cmdProfiles(args []string) int {
	if err := ensureDaemon(); err != nil {
		fmt.Fprintln(os.Stderr, "winvar:", err)
		return 1
	}
	resp, err := sendRequest(Request{Cmd: "profiles"}, 30*time.Second)
	if err != nil {
		fmt.Fprintln(os.Stderr, "winvar:", err)
		return 1
	}
	if !resp.OK {
		fmt.Fprintln(os.Stderr, "winvar:", sanitizeOutput(resp.Error))
		return 1
	}
	fmt.Print(sanitizeOutput(resp.Text))
	return 0
}

func cmdDaemon(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: winvar daemon status|start|stop|restart")
		return 2
	}
	switch args[0] {
	case "status":
		resp, err := sendRequest(Request{Cmd: "status"}, 5*time.Second)
		if err != nil || !resp.OK || resp.Status == nil {
			fmt.Println("daemon: not running")
			if err != nil {
				fmt.Println("detail:", err)
			}
			return 1
		}
		st := resp.Status
		fmt.Printf("daemon: running\nversion: %s\nuptime: %ds\nsessions: %d\ntracelog: %s\nxperf: %s\n",
			sanitizeOutput(st.Version), st.UptimeS, st.Sessions,
			sanitizeOutput(st.Tracelog), sanitizeOutput(st.Xperf))
		return 0
	case "start":
		if resp, err := sendRequest(Request{Cmd: "ping"}, time.Second); err == nil && resp.OK {
			fmt.Println("daemon: already running")
			return 0
		}
		for attempt := 0; attempt < 3; attempt++ {
			out, code, err := runCommand("schtasks.exe", "/Run", "/TN", taskName)
			if err != nil || code != 0 {
				fmt.Fprintf(os.Stderr, "winvar: cannot start task: %s %v\n", truncate(out, 500), err)
				return 1
			}
			deadline := time.Now().Add(8 * time.Second)
			for time.Now().Before(deadline) {
				if resp, err := sendRequest(Request{Cmd: "ping"}, time.Second); err == nil && resp.OK {
					fmt.Println("daemon: started")
					return 0
				}
				time.Sleep(300 * time.Millisecond)
			}
			time.Sleep(2 * time.Second)
		}
		fmt.Fprintln(os.Stderr, "winvar: daemon did not start")
		return 1
	case "stop":
		pid := daemonPid()
		resp, err := sendRequest(Request{Cmd: "shutdown"}, 10*time.Second)
		if err != nil || !resp.OK {
			fmt.Fprintln(os.Stderr, "winvar: daemon is not responding")
			return 1
		}
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := sendRequest(Request{Cmd: "ping"}, 500*time.Millisecond); err != nil {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
		deadline = time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) && processRunning(pid) {
			time.Sleep(100 * time.Millisecond)
		}
		fmt.Println("daemon: stopped")
		return 0
	case "restart":
		cmdDaemon([]string{"stop"})
		return cmdDaemon([]string{"start"})
	default:
		fmt.Fprintln(os.Stderr, "usage: winvar daemon status|start|stop|restart")
		return 2
	}
}
