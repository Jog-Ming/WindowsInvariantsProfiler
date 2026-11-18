package main

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

type ProcessResult struct {
	Process  string  `json:"process"`
	Exe      string  `json:"exe"`
	PID      int     `json:"pid"`
	Counters []int64 `json:"counters"`
	Switches int64   `json:"switches"`
	CPUMs    int64   `json:"cpu_ms"`
}

type ParseResult struct {
	Counter     string             `json:"counter"`
	Counters    []string           `json:"counters"`
	Processes   []ProcessResult    `json:"processes"`
	ByExe       map[string][]int64 `json:"by_exe"`
	SystemTotal int64              `json:"system_total"`
	Resyncs     int64              `json:"resyncs"`
	Unpaired    int64              `json:"unpaired"`
}

var (
	pmcRe  = regexp.MustCompile(`^\s+Pmc,\s*(-?\d+),\s*(-?\d+),\s*(.+)$`)
	cswRe  = regexp.MustCompile(`^\s+CSwitch,\s*(-?\d+),\s*(.+)$`)
	procRe = regexp.MustCompile(`^(.*) \((\d+)\)$`)
)

type cpuCounters struct {
	counters  []int64
	process   string
	timestamp int64
}

func sanitizeTerminal(s string, max int) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r) ||
			unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) ||
			(r >= 0xfe00 && r <= 0xfe0f) ||
			(r >= 0xe0100 && r <= 0xe01ef) {
			continue
		}
		b.WriteRune(r)
	}
	out := b.String()
	if max > 0 {
		if runes := []rune(out); len(runes) > max {
			out = string(runes[:max])
		}
	}
	return out
}

func sanitizeProcessName(s string) string { return sanitizeTerminal(s, 260) }

func sanitizeOutput(s string) string { return sanitizeTerminal(s, 0) }

func parseDump(path string) (*ParseResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	const maxDumpBytes = 256 << 20
	if st, err := f.Stat(); err == nil && st.Size() > maxDumpBytes {
		return nil, fmt.Errorf("dump file is too large: %d bytes", st.Size())
	}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	var lines []string
	for scanner.Scan() {
		if len(lines) >= 4_000_000 {
			return nil, fmt.Errorf("dump has too many lines")
		}
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	result := &ParseResult{ByExe: map[string][]int64{}}
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimLeft(line, " "), "Pmc,") {
			parts := strings.Split(line, ",")
			if len(parts) >= 4 {
				if len(parts)-3 > 64 {
					return nil, fmt.Errorf("too many counters in dump")
				}
				for _, p := range parts[3:] {
					name := sanitizeProcessName(strings.TrimSpace(p))
					if name != "" {
						result.Counters = append(result.Counters, name)
					}
				}
			}
			break
		}
	}
	if len(result.Counters) > 0 {
		result.Counter = result.Counters[0]
	}

	cpus := map[int]*cpuCounters{}
	totals := map[string][]int64{}
	switches := map[string]int64{}
	cpuMs := map[string]int64{}

	for i := 0; i < len(lines); i++ {
		m := pmcRe.FindStringSubmatch(lines[i])
		if m == nil {
			continue
		}
		rawCounters := strings.Split(m[3], ",")
		counters := make([]int64, 0, len(rawCounters))
		valid := true
		for _, raw := range rawCounters {
			v, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
			if err != nil {
				valid = false
				break
			}
			counters = append(counters, v)
		}
		if !valid {
			continue
		}
		j := i + 1
		if j < len(lines) && strings.HasPrefix(lines[j], "Error: ") {
			j++
		}
		if j >= len(lines) {
			result.Unpaired++
			continue
		}
		cm := cswRe.FindStringSubmatch(lines[j])
		if cm == nil {
			result.Unpaired++
			continue
		}
		parts := strings.Split(lines[j], ",")
		if len(parts) < 17 {
			result.Unpaired++
			continue
		}
		cpu, err := strconv.Atoi(strings.TrimSpace(parts[16]))
		if err != nil || cpu < 0 || cpu > 4096 {
			result.Unpaired++
			continue
		}
		timestamp, _ := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64)
		newProcess := strings.TrimSpace(parts[2])
		oldProcess := strings.TrimSpace(parts[8])

		if _, exists := cpus[cpu]; !exists && len(cpus) >= 4096 {
			result.Unpaired++
			i = j
			continue
		}
		prev := cpus[cpu]
		if prev != nil && len(prev.counters) == len(counters) {
			deltas := make([]int64, len(counters))
			for k := range counters {
				deltas[k] = counters[k] - prev.counters[k]
			}
			if oldProcess != prev.process {
				result.Resyncs++
			} else if oldProcess != "Idle (   0)" {
				current := totals[oldProcess]
				if current == nil {
					if len(totals) >= 4096 {
						return nil, fmt.Errorf("too many processes in dump")
					}
					current = make([]int64, len(deltas))
				} else if len(current) != len(deltas) {
					current = make([]int64, len(deltas))
				}
				for k := range deltas {
					current[k] += deltas[k]
					result.SystemTotal += deltas[k]
				}
				totals[oldProcess] = current
				switches[oldProcess]++
				cpuMs[oldProcess] += timestamp - prev.timestamp
			}
		}
		cpus[cpu] = &cpuCounters{counters: counters, process: newProcess, timestamp: timestamp}
		i = j
	}

	for name, values := range totals {
		exe := name
		pid := 0
		if m := procRe.FindStringSubmatch(name); m != nil {
			exe = m[1]
			pid, _ = strconv.Atoi(m[2])
		}
		result.Processes = append(result.Processes, ProcessResult{
			Process:  sanitizeProcessName(name),
			Exe:      sanitizeProcessName(exe),
			PID:      pid,
			Counters: values,
			Switches: switches[name],
			CPUMs:    cpuMs[name] / 10000,
		})
	}
	sort.Slice(result.Processes, func(i, j int) bool {
		a, b := result.Processes[i].Counters, result.Processes[j].Counters
		if len(a) == 0 || len(b) == 0 {
			return len(a) > len(b)
		}
		return a[0] > b[0]
	})
	for _, p := range result.Processes {
		values := result.ByExe[p.Exe]
		if values == nil {
			values = make([]int64, len(p.Counters))
		}
		for k := range p.Counters {
			if k < len(values) {
				values[k] += p.Counters[k]
			}
		}
		result.ByExe[p.Exe] = values
	}
	return result, nil
}

func printParseResult(result *ParseResult, name string, top int) {
	counter := result.Counter
	if counter == "" {
		counter = "counter"
	}
	header := fmt.Sprintf("%-46s %18s %10s %10s", "process", counter, "switches", "cpu_ms")
	fmt.Println(header)
	fmt.Println(strings.Repeat("-", len(header)))
	shown := 0
	for _, p := range result.Processes {
		if name != "" && !strings.Contains(strings.ToLower(p.Process), strings.ToLower(name)) {
			continue
		}
		value := int64(0)
		if len(p.Counters) > 0 {
			value = p.Counters[0]
		}
		fmt.Printf("%-46s %18s %10d %10d\n", p.Process, comma(value), p.Switches, p.CPUMs)
		shown++
		if top > 0 && shown >= top {
			break
		}
	}
	if len(result.Processes) == 0 {
		fmt.Println("(no PMC samples paired with context switches)")
	}
	fmt.Println()
	fmt.Printf("%-25s %18s\n", "exe (all pids)", counter)
	type exeRow struct {
		name   string
		values []int64
	}
	var rows []exeRow
	for exe, values := range result.ByExe {
		rows = append(rows, exeRow{exe, values})
	}
	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i].values, rows[j].values
		if len(a) == 0 || len(b) == 0 {
			return len(a) > len(b)
		}
		return a[0] > b[0]
	})
	shown = 0
	for _, row := range rows {
		if name != "" && !strings.Contains(strings.ToLower(row.name), strings.ToLower(name)) {
			continue
		}
		value := int64(0)
		if len(row.values) > 0 {
			value = row.values[0]
		}
		fmt.Printf("%-25s %18s\n", row.name, comma(value))
		shown++
		if top > 0 && shown >= top {
			break
		}
	}
	fmt.Println()
	fmt.Printf("system total: %s   resyncs: %d   unpaired: %d\n",
		comma(result.SystemTotal), result.Resyncs, result.Unpaired)
}
