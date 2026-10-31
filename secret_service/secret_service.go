package ss

import (
	"context"
	"fmt"
	"time"

	"errors"

	dbus "github.com/godbus/dbus/v5"
)

const (
	serviceName          = "org.freedesktop.secrets"
	servicePath          = "/org/freedesktop/secrets"
	serviceInterface     = "org.freedesktop.Secret.Service"
	collectionInterface  = "org.freedesktop.Secret.Collection"
	collectionsInterface = "org.freedesktop.Secret.Service.Collections"
	itemInterface        = "org.freedesktop.Secret.Item"
	sessionInterface     = "org.freedesktop.Secret.Session"
	promptInterface      = "org.freedesktop.Secret.Prompt"

	loginCollectionAlias = "/org/freedesktop/secrets/aliases/default"
	collectionBasePath   = "/org/freedesktop/secrets/collection/"
)

// Secret defines a org.freedesk.Secret.Item secret struct.
type Secret struct {
	Session     dbus.ObjectPath
	Parameters  []byte
	Value       []byte
	ContentType string `dbus:"content_type"`
}

// NewSecret initializes a new Secret.
func NewSecret(session dbus.ObjectPath, secret string) Secret {
	return Secret{
		Session:     session,
		Parameters:  []byte{},
		Value:       []byte(secret),
		ContentType: "text/plain; charset=utf8",
	}
}

// SecretService is an interface for the Secret Service dbus API.
type SecretService struct {
	*dbus.Conn
	object dbus.BusObject
	ctx    context.Context
}

// NewSecretService inializes a new SecretService object.
func NewSecretService() (*SecretService, error) {
	conn, err := dbus.SessionBus()
	if err != nil {
		return nil, err
	}

	return &SecretService{
		conn,
		conn.Object(serviceName, servicePath),
		context.Background(),
	}, nil
}

// NewSecretServiceWithContext uses a private connection. The caller must close
// Conn after the operation; cancellation must never close the shared session bus.
func NewSecretServiceWithContext(ctx context.Context) (*SecretService, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	conn, err := dbus.SessionBusPrivateNoAutoStartup()
	if err != nil {
		return nil, err
	}
	// Interrupt authentication/Hello if the bus accepts a connection but stalls.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	err = conn.Auth(nil)
	if err == nil {
		err = conn.Hello()
	}
	stop()
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &SecretService{Conn: conn, object: conn.Object(serviceName, servicePath), ctx: ctx}, nil
}

// cleanup gives resource release a short budget independent from cancellation.
func (s *SecretService) cleanup(fn func(context.Context)) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	fn(ctx)
}

// OpenSession opens a secret service session.
func (s *SecretService) OpenSession() (dbus.BusObject, error) {
	var disregard dbus.Variant
	var sessionPath dbus.ObjectPath
	err := s.object.CallWithContext(s.ctx, serviceInterface+".OpenSession", 0, "plain", dbus.MakeVariant("")).Store(&disregard, &sessionPath)
	if err != nil {
		return nil, err
	}

	return s.Object(serviceName, sessionPath), nil
}

// CheckCollectionPath accepts dbus path and returns nil if the path is found
// in the collection interface (and can be used).
func (s *SecretService) CheckCollectionPath(path dbus.ObjectPath) error {
	obj := s.Conn.Object(serviceName, servicePath)
	var val dbus.Variant
	err := obj.CallWithContext(s.ctx, "org.freedesktop.DBus.Properties.Get", 0, serviceInterface, "Collections").Store(&val)
	if err != nil {
		return err
	}
	paths, ok := val.Value().([]dbus.ObjectPath)
	if !ok {
		return errors.New("invalid collections response")
	}
	for _, p := range paths {
		if p == path {
			return nil
		}
	}
	return errors.New("path not found")
}

// GetCollection returns a collection from a name.
func (s *SecretService) GetCollection(name string) dbus.BusObject {
	return s.Object(serviceName, dbus.ObjectPath(collectionBasePath+name))
}

// GetLoginCollection decides and returns the dbus collection to be used for login.
func (s *SecretService) GetLoginCollection() dbus.BusObject {
	path := dbus.ObjectPath(collectionBasePath + "login")
	if err := s.CheckCollectionPath(path); err != nil {
		path = dbus.ObjectPath(loginCollectionAlias)
	}
	return s.Object(serviceName, path)
}

// Unlock unlocks a collection.
func (s *SecretService) Unlock(collection dbus.ObjectPath) error {
	var unlocked []dbus.ObjectPath
	var prompt dbus.ObjectPath
	err := s.object.CallWithContext(s.ctx, serviceInterface+".Unlock", 0, []dbus.ObjectPath{collection}).Store(&unlocked, &prompt)
	if err != nil {
		return err
	}

	_, v, err := s.handlePrompt(prompt)
	if err != nil {
		return err
	}

	collections := v.Value()
	switch c := collections.(type) {
	case []dbus.ObjectPath:
		unlocked = append(unlocked, c...)
	}

	if len(unlocked) != 1 || (collection != loginCollectionAlias && unlocked[0] != collection) {
		return fmt.Errorf("failed to unlock correct collection '%v'", collection)
	}

	return nil
}

// Close closes a secret service dbus session.
func (s *SecretService) Close(session dbus.BusObject) error {
	var err error
	s.cleanup(func(ctx context.Context) { err = session.CallWithContext(ctx, sessionInterface+".Close", 0).Err })
	return err
}

// CreateCollection with the supplied label.
func (s *SecretService) CreateCollection(label string) (dbus.BusObject, error) {
	properties := map[string]dbus.Variant{
		collectionInterface + ".Label": dbus.MakeVariant(label),
	}
	var collection, prompt dbus.ObjectPath
	err := s.object.CallWithContext(s.ctx, serviceInterface+".CreateCollection", 0, properties, "").
		Store(&collection, &prompt)
	if err != nil {
		return nil, err
	}

	_, v, err := s.handlePrompt(prompt)
	if err != nil {
		return nil, err
	}

	if v.String() != "" {
		collection = dbus.ObjectPath(v.String())
	}

	return s.Object(serviceName, collection), nil
}

// CreateItem creates an item in a collection, with label, attributes and a
// related secret.
func (s *SecretService) CreateItem(collection dbus.BusObject, label string, attributes map[string]string, secret Secret) error {
	properties := map[string]dbus.Variant{
		itemInterface + ".Label":      dbus.MakeVariant(label),
		itemInterface + ".Attributes": dbus.MakeVariant(attributes),
	}

	var item, prompt dbus.ObjectPath
	err := collection.CallWithContext(s.ctx, collectionInterface+".CreateItem", 0,
		properties, secret, true).Store(&item, &prompt)
	if err != nil {
		return err
	}

	_, _, err = s.handlePrompt(prompt)
	if err != nil {
		return err
	}

	return nil
}

// handlePrompt checks if a prompt should be handles and handles it by
// triggering the prompt and waiting for the Secret service daemon to display
// the prompt to the user.
func (s *SecretService) handlePrompt(prompt dbus.ObjectPath) (bool, dbus.Variant, error) {
	empty := dbus.MakeVariant("")
	if prompt == dbus.ObjectPath("/") {
		return false, empty, nil
	}
	options := []dbus.MatchOption{dbus.WithMatchObjectPath(prompt), dbus.WithMatchInterface(promptInterface), dbus.WithMatchMember("Completed"), dbus.WithMatchSender(serviceName)}
	if err := s.AddMatchSignalContext(s.ctx, options...); err != nil {
		return false, empty, err
	}
	defer s.cleanup(func(ctx context.Context) { _ = s.RemoveMatchSignalContext(ctx, options...) })
	signals := make(chan *dbus.Signal, 1)
	s.Signal(signals)
	defer s.RemoveSignal(signals)
	dismiss := func() {
		s.cleanup(func(ctx context.Context) {
			_ = s.Object(serviceName, prompt).CallWithContext(ctx, promptInterface+".Dismiss", 0).Err
		})
	}
	if err := s.Object(serviceName, prompt).CallWithContext(s.ctx, promptInterface+".Prompt", 0, "").Err; err != nil {
		dismiss()
		return false, empty, err
	}
	for {
		select {
		case <-s.ctx.Done():
			dismiss()
			return false, empty, s.ctx.Err()
		case signal, ok := <-signals:
			if !ok {
				return false, empty, errors.New("secret service disconnected")
			}
			if signal == nil || signal.Path != prompt || signal.Name != promptInterface+".Completed" {
				continue
			}
			if len(signal.Body) != 2 {
				return false, empty, errors.New("invalid prompt response")
			}
			dismissed, valid := signal.Body[0].(bool)
			result, valueOK := signal.Body[1].(dbus.Variant)
			if !valid || !valueOK {
				return false, empty, errors.New("invalid prompt response")
			}
			if dismissed {
				return true, empty, errors.New("secret service prompt dismissed")
			}
			return false, result, nil
		}
	}
}

// SearchItems returns a list of items matching the search object.
func (s *SecretService) SearchItems(collection dbus.BusObject, search interface{}) ([]dbus.ObjectPath, error) {
	var results []dbus.ObjectPath
	err := collection.CallWithContext(s.ctx, collectionInterface+".SearchItems", 0, search).Store(&results)
	if err != nil {
		return nil, err
	}

	return results, nil
}

// GetSecret gets secret from an item in a given session.
func (s *SecretService) GetSecret(itemPath dbus.ObjectPath, session dbus.ObjectPath) (*Secret, error) {
	var secret Secret
	err := s.Object(serviceName, itemPath).CallWithContext(s.ctx, itemInterface+".GetSecret", 0, session).Store(&secret)
	if err != nil {
		return nil, err
	}

	return &secret, nil
}

// Delete deletes an item from the collection.
func (s *SecretService) Delete(itemPath dbus.ObjectPath) error {
	var prompt dbus.ObjectPath
	err := s.Object(serviceName, itemPath).CallWithContext(s.ctx, itemInterface+".Delete", 0).Store(&prompt)
	if err != nil {
		return err
	}

	_, _, err = s.handlePrompt(prompt)
	if err != nil {
		return err
	}

	return nil
}
