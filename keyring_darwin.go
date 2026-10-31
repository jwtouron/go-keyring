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

func init() { provider = macOSXKeychain{} }

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
