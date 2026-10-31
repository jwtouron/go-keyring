package keyring

import (
	"context"
	"errors"
	"testing"
)

func TestContextMethodsRejectPreCancellation(t *testing.T) {
	old := provider
	defer func() { provider = old }()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	checks := []func() error{
		func() error { return SetWithContext(ctx, service, user, password) },
		func() error { _, err := GetWithContext(ctx, service, user); return err },
		func() error { return DeleteWithContext(ctx, service, user) },
		func() error { return DeleteAllWithContext(ctx, service) },
		func() error { _, err := ListUsersWithContext(ctx, service); return err },
	}
	for _, backend := range []string{"mock", "native", "fallback"} {
		t.Run(backend, func(t *testing.T) {
			switch backend {
			case "mock":
				MockInit()
			case "native":
				MockRestore()
			case "fallback":
				provider = fallbackServiceProvider{}
			}
			for _, call := range checks {
				if err := call(); !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			}
			if backend == "mock" {
				if _, err := Get(service, user); !errors.Is(err, ErrNotFound) {
					t.Fatal("cancelled write reached backend", err)
				}
			}
		})
	}
}

type completingProvider struct {
	mockProvider
	started, release chan struct{}
}

func (p *completingProvider) SetWithContext(ctx context.Context, _, _, _ string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	close(p.started)
	<-p.release
	return nil
}

func TestCompletedMutationKeepsActualResult(t *testing.T) {
	old := provider
	defer func() { provider = old }()
	p := &completingProvider{started: make(chan struct{}), release: make(chan struct{})}
	provider = p
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- SetWithContext(ctx, service, user, password) }()
	<-p.started
	cancel()
	close(p.release)
	if err := <-done; err != nil {
		t.Fatal("completed mutation was misreported", err)
	}
}

func TestListUsersWithContext(t *testing.T) {
	old := provider
	defer func() { provider = old }()
	MockInit()
	for _, name := range []string{"first", "second"} {
		if err := Set(service, name, password); err != nil {
			t.Fatal(err)
		}
	}
	users, err := ListUsersWithContext(context.Background(), service)
	if err != nil || len(users) != 2 {
		t.Fatalf("users=%v err=%v", users, err)
	}
	MockInitWithError(ErrNotFound)
	if _, err := ListUsersWithContext(context.Background(), service); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
}
