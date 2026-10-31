package keyring

import (
	"context"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestSecurityCommandChild(t *testing.T) {
	args := os.Args
	for index, arg := range args {
		if arg != "--" || len(args) <= index+2 {
			continue
		}
		if args[index+1] == "hang" {
			if err := os.WriteFile(args[index+2], []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
				t.Fatal(err)
			}
			for {
				time.Sleep(time.Hour)
			}
		}
		if args[index+1] == "echo" {
			data, _ := io.ReadAll(os.Stdin)
			os.Stdout.Write(data)
		}
		return
	}
}

func TestCommandCancellationReapsChild(t *testing.T) {
	marker := t.TempDir() + "/child.pid"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := runCommand(ctx, os.Args[0], "", "-test.run=^TestSecurityCommandChild$", "--", "hang", marker)
		done <- err
	}()
	var data []byte
	deadline := time.After(5 * time.Second)
	for len(data) == 0 {
		select {
		case <-deadline:
			t.Fatal("child did not start")
		default:
		}
		data, _ = os.ReadFile(marker)
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("child was not cancelled")
	}
	pid, err := strconv.Atoi(string(data))
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatal("child still exists", err)
	}
}

func TestCommandPreCancellationAndStdin(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := runCommand(ctx, "/does-not-exist", ""); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	out, err := runCommand(context.Background(), os.Args[0], "synthetic stdin", "-test.run=^TestSecurityCommandChild$", "--", "echo", "unused")
	if err != nil || !strings.HasPrefix(string(out), "synthetic stdin") {
		t.Fatal(string(out), err)
	}
	if err := (macOSXKeychain{}).SetWithContext(context.Background(), strings.Repeat("x", 4096), "user", "value"); !errors.Is(err, ErrSetDataTooBig) {
		t.Fatal(err)
	}
}
