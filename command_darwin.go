package keyring

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

func runCommand(ctx context.Context, executable, input string, args ...string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.WaitDelay = 2 * time.Second
	if input != "" {
		cmd.Stdin = strings.NewReader(input)
	}
	output, err := cmd.CombinedOutput()
	if err != nil && ctx.Err() != nil {
		return output, ctx.Err()
	}
	return output, err
}
