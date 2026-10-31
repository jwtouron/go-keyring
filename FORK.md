# Context-aware go-keyring

This fork starts from Zalando v0.2.8 (`a8cdfe320cc8bc0534c895a648dc9214715a9da5`).
Its scope is context support and the tests/CI needed to maintain it. Original module and
import paths remain `github.com/zalando/go-keyring`; consumers pin a replacement to a
reviewed commit in `github.com/jwtouron/go-keyring`. Go 1.25+ is required.

## API and cancellation

`GetWithContext`, `SetWithContext`, `DeleteWithContext`, and `DeleteAllWithContext`
take `context.Context` first. Existing functions and the `Keyring` interface remain
available; existing functions use a background context. `KeyringWithContext` describes
the new methods. Missing entries retain `ErrNotFound`.

- macOS commands use `exec.CommandContext`, carry secrets through stdin, and are reaped
  before return. Input-size validation happens before starting a subprocess.
- Linux operations own private D-Bus connections. Context reaches authentication,
  method calls, and prompt waits. Cancellation attempts prompt dismissal; cleanup has
  an independent two-second budget. One operation cannot close another's connection.
- Windows checks context before each native call; a started Credential Manager call
  finishes synchronously and reports its actual result. It does not prompt for input.

Cancellation is not rollback. A service can have accepted a write before the client
observes cancellation. Bulk deletion can complete partially. Callers must serialize
credential mutations and preserve their own durable recovery boundaries.

## Verification

`go test -race ./...` and `go vet ./...` run with an in-memory credential provider by
default. `KEYRING_OS_TEST=1` opts into the real OS store, using unique synthetic service
names and deleting only those entries. Linux tests additionally require `dbus-daemon`;
CI supplies an isolated Secret Service session. Windows ARM64 runs without the Go race
detector. Actual hosted results and native Windows verification must be reported separately
from cross-compilation or Wine checks.

The native CI matrix covers macOS/Linux/Windows x64 and ARM64. The weekly/manual upstream
workflow proposes a merge on `sync/upstream` and dispatches its tests. Enable Actions and
allow workflow-created pull requests in the fork's repository settings. Conflicts stop
automation; merges require review. BrowseFriend's dependency pin changes separately.

## Licensing

Keep the upstream MIT license and existing Apache-2.0 source headers. Downstream
distributions must include the applicable license texts and identify the fork revision.
