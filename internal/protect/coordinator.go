package protect

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"time"
)

const sudoPath = "/usr/bin/sudo"

type privilegedCommand func(context.Context, []string, []byte) error

func EmptyState(site, configSHA256 string, baselineSHA256 *string) State {
	return State{
		SchemaVersion:          1,
		Site:                   site,
		ConfigSHA256:           configSHA256,
		BaselineManifestSHA256: baselineSHA256,
		Rules:                  []Rule{},
	}
}

func InvokePrivilegedApply(
	ctx context.Context,
	executable string,
	configPath string,
	state State,
) error {
	return invokePrivilegedApply(ctx, executable, configPath, state, runSudo)
}

func invokePrivilegedApply(
	ctx context.Context,
	executable string,
	configPath string,
	state State,
	run privilegedCommand,
) error {
	if run == nil || !absoluteCleanPath(executable) || !absoluteCleanPath(configPath) {
		return errors.New("invalid privileged apply command")
	}
	payload, err := ProjectState(state)
	if err != nil {
		return err
	}
	arguments := []string{"-n", executable, "protect", "apply", "--config", configPath}
	return run(ctx, arguments, payload)
}

func runSudo(ctx context.Context, arguments []string, stdin []byte) error {
	commandContext, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	output := &limitedOutput{limit: 64 << 10}
	command := exec.CommandContext(commandContext, sudoPath, arguments...)
	command.Stdin = bytes.NewReader(stdin)
	command.Stdout = output
	command.Stderr = output
	command.WaitDelay = time.Second
	if err := command.Run(); err != nil {
		if contextErr := commandContext.Err(); contextErr != nil {
			return contextErr
		}
		return fmt.Errorf("privileged apply failed: %w", err)
	}
	return nil
}
