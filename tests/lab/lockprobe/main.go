// lockprobe verifies cross-process and cross-node lock primitives.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

const busyExitCode = 10

var errLockBusy = errors.New("lock is held by another process")

func acquireRecord(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock file: %w", err)
	}

	lock := unix.Flock_t{
		Type:   unix.F_WRLCK,
		Whence: 0,
		Start:  0,
		Len:    0,
	}
	if err := unix.FcntlFlock(file.Fd(), unix.F_SETLK, &lock); err != nil {
		_ = file.Close()
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EACCES) {
			return nil, errLockBusy
		}
		return nil, fmt.Errorf("acquire record lock: %w", err)
	}

	return file, nil
}

func acquireExclusive(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if errors.Is(err, os.ErrExist) {
		return nil, errLockBusy
	}
	if err != nil {
		return nil, fmt.Errorf("create exclusive lock file: %w", err)
	}
	if _, err := fmt.Fprintf(file, "%d\n", os.Getpid()); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("write exclusive lock owner: %w", err)
	}
	return file, nil
}

func run(path, mode string, hold time.Duration) error {
	var file *os.File
	var err error
	switch mode {
	case "record":
		file, err = acquireRecord(path)
	case "exclusive":
		file, err = acquireExclusive(path)
	default:
		return fmt.Errorf("unsupported lock mode %q", mode)
	}
	if err != nil {
		return err
	}
	defer func() {
		_ = file.Close()
		if mode == "exclusive" {
			_ = os.Remove(path)
		}
	}()

	fmt.Println("acquired")
	if hold > 0 {
		time.Sleep(hold)
	}
	return nil
}

func main() {
	path := flag.String("path", "", "file on which to acquire the lock")
	mode := flag.String("mode", "record", "lock primitive: record or exclusive")
	hold := flag.Duration("hold", 0, "duration for which to hold the lock")
	flag.Parse()

	if *path == "" {
		fmt.Fprintln(os.Stderr, "-path is required")
		os.Exit(2)
	}
	if err := run(*path, *mode, *hold); err != nil {
		if errors.Is(err, errLockBusy) {
			fmt.Println("busy")
			os.Exit(busyExitCode)
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
