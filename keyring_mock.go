package keyring

import "context"

type mockProvider struct {
	mockStore map[string]map[string]string
	mockError error
}

// Set stores user and pass in the keyring under the defined service
// name.
func (m *mockProvider) SetWithContext(ctx context.Context, service, user, pass string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if m.mockError != nil {
		return m.mockError
	}
	if m.mockStore == nil {
		m.mockStore = make(map[string]map[string]string)
	}
	if m.mockStore[service] == nil {
		m.mockStore[service] = make(map[string]string)
	}
	m.mockStore[service][user] = pass
	return nil
}

// Get gets a secret from the keyring given a service name and a user.
func (m *mockProvider) GetWithContext(ctx context.Context, service, user string) (string, error) {
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	if m.mockError != nil {
		return "", m.mockError
	}
	if b, ok := m.mockStore[service]; ok {
		if v, ok := b[user]; ok {
			return v, nil
		}
	}
	return "", ErrNotFound
}

// Delete deletes a secret, identified by service & user, from the keyring.
func (m *mockProvider) DeleteWithContext(ctx context.Context, service, user string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if m.mockError != nil {
		return m.mockError
	}
	if m.mockStore != nil {
		if _, ok := m.mockStore[service]; ok {
			if _, ok := m.mockStore[service][user]; ok {
				delete(m.mockStore[service], user)
				return nil
			}
		}
	}
	return ErrNotFound
}

// DeleteAll deletes all secrets for a given service
func (m *mockProvider) DeleteAllWithContext(ctx context.Context, service string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if m.mockError != nil {
		return m.mockError
	}
	delete(m.mockStore, service)
	return nil
}

// MockInit sets the provider to a mocked memory store
func MockInit() {
	provider = &mockProvider{}
}

// MockInitWithError sets the provider to a mocked memory store
// that returns the given error on all operations
func MockInitWithError(err error) {
	provider = &mockProvider{mockError: err}
}

// Legacy provider methods retain the original Keyring interface.
func (k *mockProvider) Get(s, u string) (string, error) {
	return k.GetWithContext(context.Background(), s, u)
}
func (k *mockProvider) Set(s, u, p string) error {
	return k.SetWithContext(context.Background(), s, u, p)
}
func (k *mockProvider) Delete(s, u string) error {
	return k.DeleteWithContext(context.Background(), s, u)
}
func (k *mockProvider) DeleteAll(s string) error {
	return k.DeleteAllWithContext(context.Background(), s)
}
