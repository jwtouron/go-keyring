// Copyright 2013 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package keyring

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/zalando/go-keyring/internal/shellescape"
)

const (
	execPathKeychain     = "/usr/bin/security"
	encodingPrefix       = "go-keyring-encoded:"
	base64EncodingPrefix = "go-keyring-base64:"
)

type macOSXKeychain struct{}

// runSecurity validates before spawning and always waits for the child to exit.
func runSecurity(ctx context.Context, input string, args ...string) ([]byte, error) {
	return runCommand(ctx, execPathKeychain, input, args...)
}

func (k macOSXKeychain) GetWithContext(ctx context.Context, service, username string) (string, error) {
	out, err := runSecurity(ctx, "", "find-generic-password", "-s", service, "-wa", username)
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() == 44 {
			return "", ErrNotFound
		}
		return "", err
	}
	value := strings.TrimSpace(string(out))
	if strings.HasPrefix(value, encodingPrefix) {
		decoded, err := hex.DecodeString(strings.TrimPrefix(value, encodingPrefix))
		return string(decoded), err
	}
	if strings.HasPrefix(value, base64EncodingPrefix) {
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(value, base64EncodingPrefix))
		return string(decoded), err
	}
	return value, nil
}

func (k macOSXKeychain) SetWithContext(ctx context.Context, service, username, password string) error {
	password = base64EncodingPrefix + base64.StdEncoding.EncodeToString([]byte(password))
	command := fmt.Sprintf("add-generic-password -U -s %s -a %s -w %s\n", shellescape.Quote(service), shellescape.Quote(username), shellescape.Quote(password))
	if len(command) >= 4096 {
		return ErrSetDataTooBig
	}
	_, err := runSecurity(ctx, command, "-i")
	return err
}

func (k macOSXKeychain) DeleteWithContext(ctx context.Context, service, username string) error {
	_, err := runSecurity(ctx, "", "delete-generic-password", "-s", service, "-a", username)
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 44 {
		return ErrNotFound
	}
	return err
}

func (k macOSXKeychain) DeleteAllWithContext(ctx context.Context, service string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if service == "" {
		return ErrNotFound
	}
	for {
		_, err := runSecurity(ctx, "", "delete-generic-password", "-s", service)
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() == 44 {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// Legacy provider methods retain the original Keyring interface.
func (k macOSXKeychain) Get(s, u string) (string, error) {
	return k.GetWithContext(context.Background(), s, u)
}
func (k macOSXKeychain) Set(s, u, p string) error {
	return k.SetWithContext(context.Background(), s, u, p)
}
func (k macOSXKeychain) Delete(s, u string) error {
	return k.DeleteWithContext(context.Background(), s, u)
}
func (k macOSXKeychain) DeleteAll(s string) error {
	return k.DeleteAllWithContext(context.Background(), s)
}

// ListUsers returns a list of all users for a given service
func (k macOSXKeychain) ListUsersWithContext(ctx context.Context, service string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if service == "" {
		return []string{}, nil
	}

	// Get the default keychain since there can be multiple keychains
	defaultKeychainOut, err := runSecurity(ctx, "", "default-keychain")
	if err != nil {
		return nil, err
	}
	// Take first line in case multiple default keychains are returned
	firstLine := strings.SplitN(strings.TrimSpace(string(defaultKeychainOut)), "\n", 2)[0]
	defaultKeychain := strings.Trim(strings.TrimSpace(firstLine), `"`)

	// dump-keychain (not dump-keyring) requires a keychain path
	out, err := runSecurity(ctx, "", "dump-keychain", defaultKeychain)
	if err != nil {
		return nil, err
	}

	var users []string
	seenUsers := make(map[string]bool)
	var currentKeychain, currentSvc, currentAcct string
	lines := strings.Split(string(out), "\n")

	for _, line := range lines {
		switch {
		case strings.HasPrefix(strings.TrimSpace(line), "keychain:"):
			if currentKeychain == defaultKeychain && currentSvc == service && currentAcct != "" && !seenUsers[currentAcct] {
				seenUsers[currentAcct] = true
				users = append(users, currentAcct)
			}
			currentKeychain = strings.Trim(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "keychain:")), `"`)
			currentSvc = ""
			currentAcct = ""
		case strings.Contains(line, `"svce"`):
			currentSvc = parseDumpKeychainBlob(line)
		case strings.Contains(line, `"acct"`):
			currentAcct = parseDumpKeychainBlob(line)
		}
	}
	if currentKeychain == defaultKeychain && currentSvc == service && currentAcct != "" && !seenUsers[currentAcct] {
		users = append(users, currentAcct)
	}

	return users, nil
}

func parseDumpKeychainBlob(line string) string {
	idx := strings.Index(line, `="`)
	if idx == -1 {
		return ""
	}
	start := idx + 2
	end := strings.Index(line[start:], `"`)
	if end == -1 {
		return ""
	}
	return line[start : start+end]
}

func init() {
	p := macOSXKeychain{}
	provider = p
	restoreProvider = func() { provider = p }
}

func (k macOSXKeychain) ListUsers(service string) ([]string, error) {
	return k.ListUsersWithContext(context.Background(), service)
}
