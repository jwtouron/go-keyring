//go:build (dragonfly && cgo) || (freebsd && cgo) || linux || netbsd || openbsd

package keyring

import (
	"context"
	"fmt"

	dbus "github.com/godbus/dbus/v5"
	ss "github.com/zalando/go-keyring/secret_service"
)

type secretServiceProvider struct{}

// Set stores user and pass in the keyring under the defined service
// name.
func (s secretServiceProvider) SetWithContext(ctx context.Context, service, user, pass string) error {
	svc, err := ss.NewSecretServiceWithContext(ctx)
	if err != nil {
		return err
	}
	defer svc.Conn.Close()

	// open a session
	session, err := svc.OpenSession()
	if err != nil {
		return err
	}
	defer svc.Close(session)

	attributes := map[string]string{
		"username": user,
		"service":  service,
	}

	secret := ss.NewSecret(session.Path(), pass)

	collection := svc.GetLoginCollection()

	err = svc.Unlock(collection.Path())
	if err != nil {
		return err
	}

	err = svc.CreateItem(collection,
		fmt.Sprintf("Password for '%s' on '%s'", user, service),
		attributes, secret)
	if err != nil {
		return err
	}

	return nil
}

// findItem looksup an item by service and user.
func (s secretServiceProvider) findItem(svc *ss.SecretService, service, user string) (dbus.ObjectPath, error) {
	collection := svc.GetLoginCollection()

	search := map[string]string{
		"username": user,
		"service":  service,
	}

	err := svc.Unlock(collection.Path())
	if err != nil {
		return "", err
	}

	results, err := svc.SearchItems(collection, search)
	if err != nil {
		return "", err
	}

	if len(results) == 0 {
		return "", ErrNotFound
	}

	return results[0], nil
}

// findServiceItems looksup all items by service.
func (s secretServiceProvider) findServiceItems(svc *ss.SecretService, service string) ([]dbus.ObjectPath, error) {
	collection := svc.GetLoginCollection()

	search := map[string]string{
		"service": service,
	}

	err := svc.Unlock(collection.Path())
	if err != nil {
		return []dbus.ObjectPath{}, err
	}

	results, err := svc.SearchItems(collection, search)
	if err != nil {
		return []dbus.ObjectPath{}, err
	}

	if len(results) == 0 {
		return []dbus.ObjectPath{}, ErrNotFound
	}

	return results, nil
}

// Get gets a secret from the keyring given a service name and a user.
func (s secretServiceProvider) GetWithContext(ctx context.Context, service, user string) (string, error) {
	svc, err := ss.NewSecretServiceWithContext(ctx)
	if err != nil {
		return "", err
	}
	defer svc.Conn.Close()

	item, err := s.findItem(svc, service, user)
	if err != nil {
		return "", err
	}

	// open a session
	session, err := svc.OpenSession()
	if err != nil {
		return "", err
	}
	defer svc.Close(session)

	// unlock if invdividual item is locked
	err = svc.Unlock(item)
	if err != nil {
		return "", err
	}

	secret, err := svc.GetSecret(item, session.Path())
	if err != nil {
		return "", err
	}

	return string(secret.Value), nil
}

// Delete deletes a secret, identified by service & user, from the keyring.
func (s secretServiceProvider) DeleteWithContext(ctx context.Context, service, user string) error {
	svc, err := ss.NewSecretServiceWithContext(ctx)
	if err != nil {
		return err
	}
	defer svc.Conn.Close()

	item, err := s.findItem(svc, service, user)
	if err != nil {
		return err
	}

	return svc.Delete(item)
}

// DeleteAll deletes all secrets for a given service
func (s secretServiceProvider) DeleteAllWithContext(ctx context.Context, service string) error {
	// if service is empty, do nothing otherwise it might accidentally delete all secrets
	if service == "" {
		return ErrNotFound
	}

	svc, err := ss.NewSecretServiceWithContext(ctx)
	if err != nil {
		return err
	}
	defer svc.Conn.Close()
	// find all items for the service
	items, err := s.findServiceItems(svc, service)
	if err != nil {
		if err == ErrNotFound {
			return nil
		}
		return err
	}
	for _, item := range items {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		err = svc.Delete(item)
		if err != nil {
			return err
		}
	}
	return nil
}

func init() {
	provider = secretServiceProvider{}
}

// Legacy provider methods retain the original Keyring interface.
func (k secretServiceProvider) Get(s, u string) (string, error) {
	return k.GetWithContext(context.Background(), s, u)
}
func (k secretServiceProvider) Set(s, u, p string) error {
	return k.SetWithContext(context.Background(), s, u, p)
}
func (k secretServiceProvider) Delete(s, u string) error {
	return k.DeleteWithContext(context.Background(), s, u)
}
func (k secretServiceProvider) DeleteAll(s string) error {
	return k.DeleteAllWithContext(context.Background(), s)
}
