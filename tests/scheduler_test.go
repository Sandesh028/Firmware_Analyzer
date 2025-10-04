package tests

import (
	"context"
	"io"
	"log"
	"sync"
	"testing"

	"firmwareanalyzer/pkg/scheduler"
)

func TestSchedulerLocalAndRemote(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	var commands [][]string
	execFn := scheduler.ExecFunc(func(ctx context.Context, name string, args ...string) error {
		mu.Lock()
		defer mu.Unlock()
		cmd := append([]string{name}, args...)
		commands = append(commands, cmd)
		return nil
	})

	opts := scheduler.Options{
		AnalyzerPath:   "analyzer-bin",
		Concurrency:    2,
		Logger:         log.New(io.Discard, "sched", log.LstdFlags),
		LocalExecutor:  execFn,
		RemoteExecutor: execFn,
		RemoteHosts: map[string]scheduler.RemoteHost{
			"remote": {Name: "remote", Address: "remote.example", User: "root", AnalyzerPath: "/opt/analyzer", SSHBinary: "ssh"},
		},
	}
	sched := scheduler.New(opts)
	results := sched.Start(context.Background())

	done := make(chan []scheduler.Result)
	go func() {
		var res []scheduler.Result
		for r := range results {
			res = append(res, r)
		}
		done <- res
	}()

	localJob := scheduler.Job{Firmware: "fw1.bin", OutputDir: "/tmp/out1", HistoryDir: "history", ReportFormats: []string{"json"}}
	if err := sched.Enqueue(localJob); err != nil {
		t.Fatalf("enqueue local: %v", err)
	}
	remoteJob := scheduler.Job{Firmware: "fw2.bin", OutputDir: "/tmp/out2", RemoteHost: "remote", ExtraArgs: []string{"--enable-osv"}}
	if err := sched.Enqueue(remoteJob); err != nil {
		t.Fatalf("enqueue remote: %v", err)
	}

	sched.Close()
	got := <-done

	if len(got) != 2 {
		t.Fatalf("expected 2 results, got %d", len(got))
	}

	mu.Lock()
	defer mu.Unlock()
	if len(commands) != 2 {
		t.Fatalf("expected 2 commands, got %d", len(commands))
	}
	expected := [][]string{
		{"analyzer-bin", "--fw", "fw1.bin", "--out", "/tmp/out1", "--history-dir", "history", "--report-formats", "json"},
		{"ssh", "root@remote.example", "/opt/analyzer", "--fw", "fw2.bin", "--out", "/tmp/out2", "--enable-osv"},
	}
	for _, want := range expected {
		found := false
		for _, cmd := range commands {
			if equalSlices(cmd, want) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("expected command %v not observed: %v", want, commands)
		}
	}
}

func equalSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
