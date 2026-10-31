package ss

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	dbus "github.com/godbus/dbus/v5"
)

func privateBus(t *testing.T) string {
	t.Helper()
	command, err := exec.LookPath("dbus-daemon")
	if err != nil {
		t.Skip("requires dbus-daemon")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	cmd := exec.CommandContext(ctx, command, "--session", "--nofork", "--print-address=1")
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); _ = cmd.Wait() })
	address, err := bufio.NewReader(out).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(address)
}

type promptFixture struct {
	conn               *dbus.Conn
	started, dismissed chan struct{}
	once               sync.Once
	complete           bool
}

func (p *promptFixture) Prompt(string) *dbus.Error {
	close(p.started)
	if p.complete {
		_ = p.conn.Emit("/test/prompt", promptInterface+".Completed", false, dbus.MakeVariant("done"))
	}
	return nil
}
func (p *promptFixture) Dismiss() *dbus.Error {
	p.once.Do(func() { close(p.dismissed) })
	_ = p.conn.Emit("/test/prompt", promptInterface+".Completed", true, dbus.MakeVariant(""))
	return nil
}

type stalledSecret struct{ started, release chan struct{} }

func (p *stalledSecret) GetSecret(dbus.ObjectPath) (Secret, *dbus.Error) {
	close(p.started)
	<-p.release
	return Secret{Value: []byte("synthetic")}, nil
}

type attributesFixture struct {
	started, release chan struct{}
	value            any
}

func (p *attributesFixture) Get(iface, property string) (dbus.Variant, *dbus.Error) {
	if iface != itemInterface || property != "Attributes" {
		return dbus.Variant{}, dbus.MakeFailedError(errors.New("unexpected property"))
	}
	close(p.started)
	<-p.release
	return dbus.MakeVariant(p.value), nil
}

func TestItemAttributesContextAndValidation(t *testing.T) {
	for _, outcome := range []string{"cancel", "complete", "malformed"} {
		t.Run(outcome, func(t *testing.T) {
			server, base := fakeService(t)
			fixture := &attributesFixture{
				started: make(chan struct{}), release: make(chan struct{}),
				value: map[string]string{"username": "synthetic"},
			}
			if outcome == "malformed" {
				fixture.value = "invalid attributes"
			}
			defer close(fixture.release)
			if err := server.Export(fixture, "/test/item", "org.freedesktop.DBus.Properties"); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(base)
			defer cancel()
			service, err := NewSecretServiceWithContext(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer service.Conn.Close()
			done := make(chan error, 1)
			go func() {
				attrs, err := service.GetItemAttributes("/test/item")
				if outcome == "complete" && attrs["username"] != "synthetic" {
					err = errors.New("attributes not preserved")
				}
				done <- err
			}()
			<-fixture.started
			if outcome == "cancel" {
				cancel()
			} else {
				fixture.release <- struct{}{}
			}
			select {
			case err := <-done:
				if outcome == "cancel" && !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
				if outcome == "complete" && err != nil || outcome == "malformed" && err == nil {
					t.Fatalf("%s: %v", outcome, err)
				}
			case <-time.After(time.Second):
				t.Fatal("attribute request did not finish")
			}
		})
	}
}

func fakeService(t *testing.T) (*dbus.Conn, context.Context) {
	t.Helper()
	address := privateBus(t)
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", address)
	server, err := dbus.Connect(address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	if reply, err := server.RequestName(serviceName, dbus.NameFlagDoNotQueue); err != nil || reply != dbus.RequestNameReplyPrimaryOwner {
		t.Fatal(reply, err)
	}
	return server, context.Background()
}

func TestPromptCancellationAndCompletion(t *testing.T) {
	for _, complete := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel", true: "complete"}[complete], func(t *testing.T) {
			server, base := fakeService(t)
			fixture := &promptFixture{conn: server, started: make(chan struct{}), dismissed: make(chan struct{}), complete: complete}
			if err := server.Export(fixture, "/test/prompt", promptInterface); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(base)
			defer cancel()
			service, err := NewSecretServiceWithContext(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer service.Conn.Close()
			done := make(chan error, 1)
			go func() { _, _, err := service.handlePrompt("/test/prompt"); done <- err }()
			<-fixture.started
			if !complete {
				cancel()
			}
			select {
			case err := <-done:
				if complete && err != nil {
					t.Fatal(err)
				}
				if !complete && !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("prompt wait did not end")
			}
			if !complete {
				select {
				case <-fixture.dismissed:
				case <-time.After(time.Second):
					t.Fatal("prompt not dismissed")
				}
			}
		})
	}
}

func TestCancelledCallDoesNotCloseOtherConnection(t *testing.T) {
	server, base := fakeService(t)
	fixture := &stalledSecret{started: make(chan struct{}), release: make(chan struct{})}
	defer close(fixture.release)
	if err := server.Export(fixture, "/test/item", itemInterface); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(base)
	defer cancel()
	first, err := NewSecretServiceWithContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Conn.Close()
	second, err := NewSecretServiceWithContext(base)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Conn.Close()
	done := make(chan error, 1)
	go func() { _, err := first.GetSecret("/test/item", "/test/session"); done <- err }()
	<-fixture.started
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("D-Bus call did not cancel")
	}
	if err := second.Conn.BusObject().Call("org.freedesktop.DBus.GetId", 0).Err; err != nil {
		t.Fatal("independent connection was closed", err)
	}
}

func TestCancellationDuringBusAuthenticationClosesSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stalled.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path="+path)
	closed := make(chan struct{})
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(io.Discard, conn)
		close(closed)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := NewSecretServiceWithContext(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("authentication socket left open")
	}
}
