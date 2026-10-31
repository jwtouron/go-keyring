package keyring

import (
	"context"
	"slices"
	"sort"
	"strings"
	"syscall"

	"github.com/danieljoos/wincred"
)

type windowsKeychain struct{}

// Get gets a secret from the keyring given a service name and a user.
func (k windowsKeychain) GetWithContext(ctx context.Context, service, username string) (string, error) {
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	cred, err := wincred.GetGenericCredential(k.credName(service, username))
	if err != nil {
		if err == syscall.ERROR_NOT_FOUND {
			return "", ErrNotFound
		}
		return "", err
	}

	return string(cred.CredentialBlob), nil
}

// Set stores stores user and pass in the keyring under the defined service
// name.
func (k windowsKeychain) SetWithContext(ctx context.Context, service, username, password string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	// password may not exceed 2560 bytes (https://github.com/jaraco/keyring/issues/540#issuecomment-968329967)
	if len(password) > 2560 {
		return ErrSetDataTooBig
	}

	// service may not exceed 512 bytes (might need more testing)
	if len(service) >= 512 {
		return ErrSetDataTooBig
	}

	// service may not exceed 32k but problems occur before that
	// so we limit it to 30k
	if len(service) > 1024*30 {
		return ErrSetDataTooBig
	}

	cred := wincred.NewGenericCredential(k.credName(service, username))
	cred.UserName = username
	cred.CredentialBlob = []byte(password)
	return cred.Write()
}

// Delete deletes a secret, identified by service & user, from the keyring.
func (k windowsKeychain) DeleteWithContext(ctx context.Context, service, username string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	cred, err := wincred.GetGenericCredential(k.credName(service, username))
	if err != nil {
		if err == syscall.ERROR_NOT_FOUND {
			return ErrNotFound
		}
		return err
	}

	return cred.Delete()
}

func (k windowsKeychain) DeleteAllWithContext(ctx context.Context, service string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	// if service is empty, do nothing otherwise it might accidentally delete all secrets
	if service == "" {
		return ErrNotFound
	}

	creds, err := wincred.List()
	if err != nil {
		return err
	}

	prefix := k.credName(service, "")
	deletedCount := 0

	for _, cred := range creds {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if strings.HasPrefix(cred.TargetName, prefix) {
			genericCred, err := wincred.GetGenericCredential(cred.TargetName)
			if err != nil {
				if err != syscall.ERROR_NOT_FOUND {
					return err
				}
			} else {
				err := genericCred.Delete()
				if err != nil {
					return err
				}
				deletedCount++
			}
		}
	}
	return nil
}

// ListUsers returns a list of all users for a given service
func (k windowsKeychain) ListUsersWithContext(ctx context.Context, service string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if service == "" {
		return []string{}, nil
	}

	creds, err := wincred.List()
	if err != nil {
		return nil, err
	}

	prefix := k.credName(service, "")
	var users []string

	for _, cred := range creds {
		if strings.HasPrefix(cred.TargetName, prefix) {
			username := strings.TrimPrefix(cred.TargetName, prefix)
			if username != "" {
				users = append(users, username)
			}
		}
	}
	sort.Strings(users)
	return slices.Compact(users), nil
}

// credName combines service and username to a single string.
func (k windowsKeychain) credName(service, username string) string {
	return service + ":" + username
}

func init() {
	p := windowsKeychain{}
	provider = p
	restoreProvider = func() { provider = p }
}

// Legacy provider methods retain the original Keyring interface.
func (k windowsKeychain) Get(s, u string) (string, error) {
	return k.GetWithContext(context.Background(), s, u)
}
func (k windowsKeychain) Set(s, u, p string) error {
	return k.SetWithContext(context.Background(), s, u, p)
}
func (k windowsKeychain) Delete(s, u string) error {
	return k.DeleteWithContext(context.Background(), s, u)
}
func (k windowsKeychain) DeleteAll(s string) error {
	return k.DeleteAllWithContext(context.Background(), s)
}

func (k windowsKeychain) ListUsers(service string) ([]string, error) {
	return k.ListUsersWithContext(context.Background(), service)
}
