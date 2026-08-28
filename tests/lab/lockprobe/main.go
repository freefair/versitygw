// lockprobe verifies cross-process and cross-node POSIX record locking.
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

func acquire(path string) (*os.File, error) {
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

func run(path string, hold time.Duration) error {
	file, err := acquire(path)
	if err != nil {
		return err
	}
	defer file.Close()

	fmt.Println("acquired")
	if hold > 0 {
		time.Sleep(hold)
	}
	return nil
}

func main() {
	path := flag.String("path", "", "file on which to acquire a whole-file write lock")
	hold := flag.Duration("hold", 0, "duration for which to hold the lock")
	flag.Parse()

	if *path == "" {
		fmt.Fprintln(os.Stderr, "-path is required")
		os.Exit(2)
	}
	if err := run(*path, *hold); err != nil {
		if errors.Is(err, errLockBusy) {
			fmt.Println("busy")
			os.Exit(busyExitCode)
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
