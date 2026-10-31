package keyring

import (
	"context"
	"errors"
	"runtime"
)

// All of the following methods error out on unsupported platforms
var ErrUnsupportedPlatform = errors.New("unsupported platform: " + runtime.GOOS)

type fallbackServiceProvider struct{}

func (fallbackServiceProvider) SetWithContext(ctx context.Context, service, user, pass string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return ErrUnsupportedPlatform
}

func (fallbackServiceProvider) GetWithContext(ctx context.Context, service, user string) (string, error) {
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	return "", ErrUnsupportedPlatform
}

func (fallbackServiceProvider) DeleteWithContext(ctx context.Context, service, user string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return ErrUnsupportedPlatform
}

func (fallbackServiceProvider) DeleteAllWithContext(ctx context.Context, service string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return ErrUnsupportedPlatform
}

// Legacy provider methods retain the original Keyring interface.
func (k fallbackServiceProvider) Get(s, u string) (string, error) {
	return k.GetWithContext(context.Background(), s, u)
}
func (k fallbackServiceProvider) Set(s, u, p string) error {
	return k.SetWithContext(context.Background(), s, u, p)
}
func (k fallbackServiceProvider) Delete(s, u string) error {
	return k.DeleteWithContext(context.Background(), s, u)
}
func (k fallbackServiceProvider) DeleteAll(s string) error {
	return k.DeleteAllWithContext(context.Background(), s)
}
