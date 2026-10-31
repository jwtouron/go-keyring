package keyring

import (
	"context"
	"errors"
)

// provider set in the init function by the relevant os file e.g.:
// keyring_unix.go
var provider KeyringWithContext = fallbackServiceProvider{}

// restoreProvider is set by platform init to restore the real provider after MockInit
var restoreProvider func()

var (
	// ErrNotFound is the expected error if the secret isn't found in the
	// keyring.
	ErrNotFound = errors.New("secret not found in keyring")
	// ErrSetDataTooBig is returned if `Set` was called with too much data.
	// On MacOS: The combination of service, username & password should not exceed ~3000 bytes
	// On Windows: The service is limited to 32KiB while the password is limited to 2560 bytes
	// On Linux/Unix: There is no theoretical limit but performance suffers with big values (>100KiB)
	ErrSetDataTooBig = errors.New("data passed to Set was too big")
)

// Keyring provides a simple set/get interface for a keyring service.
type Keyring interface {
	// Set password in keyring for user.
	Set(service, user, password string) error
	// Get password from keyring given service and user name.
	Get(service, user string) (string, error)
	// Delete secret from keyring.
	Delete(service, user string) error
	// DeleteAll deletes all secrets for a given service
	DeleteAll(service string) error
	// ListUsers returns a list of all users for a given service
	ListUsers(service string) ([]string, error)
}

// KeyringWithContext provides cancellation where supported by the OS backend.
// Cancellation cannot roll back a write already accepted by the credential service.
// Windows calls check the context before starting, then complete synchronously.
type KeyringWithContext interface {
	SetWithContext(context.Context, string, string, string) error
	GetWithContext(context.Context, string, string) (string, error)
	DeleteWithContext(context.Context, string, string) error
	DeleteAllWithContext(context.Context, string) error
	ListUsersWithContext(context.Context, string) ([]string, error)
}

// Set stores a password using a background context.
func Set(service, user, password string) error {
	return SetWithContext(context.Background(), service, user, password)
}

// Get reads a password using a background context.
func Get(service, user string) (string, error) {
	return GetWithContext(context.Background(), service, user)
}

// Delete removes a password using a background context.
func Delete(service, user string) error {
	return DeleteWithContext(context.Background(), service, user)
}

// DeleteAll removes a service's passwords using a background context.
func DeleteAll(service string) error { return DeleteAllWithContext(context.Background(), service) }

// SetWithContext stores a password. Cancellation does not imply the write was undone.
func SetWithContext(ctx context.Context, service, user, password string) error {
	return provider.SetWithContext(ctx, service, user, password)
}

// GetWithContext reads a password, respecting cancellation supported by the backend.
func GetWithContext(ctx context.Context, service, user string) (string, error) {
	return provider.GetWithContext(ctx, service, user)
}

// DeleteWithContext removes a password. A completed deletion cannot be rolled back.
func DeleteWithContext(ctx context.Context, service, user string) error {
	return provider.DeleteWithContext(ctx, service, user)
}

// DeleteAllWithContext removes a service's passwords and can complete partially.
func DeleteAllWithContext(ctx context.Context, service string) error {
	return provider.DeleteAllWithContext(ctx, service)
}

// ListUsers returns a list of all users for a given service
func ListUsers(service string) ([]string, error) {
	return ListUsersWithContext(context.Background(), service)
}

// ListUsersWithContext lists users, respecting cancellation supported by the backend.
func ListUsersWithContext(ctx context.Context, service string) ([]string, error) {
	return provider.ListUsersWithContext(ctx, service)
}
