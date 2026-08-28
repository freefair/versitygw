package main

import (
	"bufio"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestRecordLockBlocksAnotherProcess(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "coordinator.lock")
	command := exec.Command(os.Args[0], "-test.run=TestLockHolderProcess")
	command.Env = append(os.Environ(),
		"LOCKPROBE_HELPER=1",
		"LOCKPROBE_PATH="+lockPath,
	)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = command.Process.Kill()
		_ = command.Wait()
	})

	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() || scanner.Text() != "acquired" {
		t.Fatalf("lock holder did not become ready: %q", scanner.Text())
	}

	file, err := acquire(lockPath)
	if file != nil {
		_ = file.Close()
	}
	if !errors.Is(err, errLockBusy) {
		t.Fatalf("acquire() error = %v, want %v", err, errLockBusy)
	}
}

func TestLockHolderProcess(t *testing.T) {
	if os.Getenv("LOCKPROBE_HELPER") != "1" {
		return
	}
	if err := run(os.Getenv("LOCKPROBE_PATH"), 30*time.Second); err != nil {
		t.Fatal(err)
	}
}
