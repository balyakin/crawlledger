package protect

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"time"

	"github.com/balyakin/crawlledger/internal/atomicfile"
)

const nginxPreflightLimit = 16 << 20
const activeMapLimit = 1 << 20

type ExecuteCommand func(context.Context, string, ...string) ([]byte, error)

type CommandExecutor struct {
	Timeout     time.Duration
	OutputLimit int
}

type RollbackError struct {
	Apply    error
	Rollback error
}

type SetupResult struct {
	HTTPIncluded   bool
	ServerIncluded bool
	ActiveIncluded bool
}

type previousManagedFile struct {
	name   string
	data   []byte
	exists bool
}

func (failure *RollbackError) Error() string {
	return "Nginx rollback failed"
}

func (failure *RollbackError) Unwrap() []error {
	return []error{failure.Apply, failure.Rollback}
}

func IsRollbackFailure(err error) bool {
	var failure *RollbackError
	return errors.As(err, &failure)
}

func ValidateApplyRequest(config Config, configSHA256 string, state State, payload []byte) ([]ApplyRule, error) {
	if err := state.Validate(); err != nil {
		return nil, err
	}
	if state.Site != config.Site || state.ConfigSHA256 != configSHA256 || len(state.Rules) > config.Action.MaxActiveRules {
		return nil, errors.New("persisted state does not match the protection config")
	}
	for _, rule := range state.Rules {
		if config.actionExcluded(rule.Method, rule.PathPrefix) {
			return nil, errors.New("persisted state contains an excluded action")
		}
	}
	canonicalPayload, err := DecodeApplyPayload(payload)
	if err != nil {
		return nil, err
	}
	projection, err := ProjectState(state)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonicalPayload, projection) {
		return nil, errors.New("apply payload does not match persisted desired state")
	}
	return projectRules(state.Rules), nil
}

func (executor CommandExecutor) Run(
	ctx context.Context,
	binary string,
	arguments ...string,
) ([]byte, error) {
	if !absoluteCleanPath(binary) || executor.Timeout <= 0 || executor.OutputLimit <= 0 {
		return nil, errors.New("invalid command configuration")
	}
	commandContext, cancel := context.WithTimeout(ctx, executor.Timeout)
	defer cancel()
	output := &limitedOutput{limit: executor.OutputLimit}
	command := exec.CommandContext(commandContext, binary, arguments...)
	command.Stdout = output
	command.Stderr = output
	command.WaitDelay = time.Second
	err := command.Run()
	if contextErr := commandContext.Err(); contextErr != nil {
		return output.Bytes(), contextErr
	}
	if output.Truncated() {
		return output.Bytes(), errors.Join(err, errors.New("command output exceeds configured limit"))
	}
	if err != nil {
		return output.Bytes(), fmt.Errorf("command failed: %w", err)
	}
	return output.Bytes(), nil
}

func ApplyActiveMap(
	ctx context.Context,
	config Config,
	rules []ApplyRule,
	execute ExecuteCommand,
) error {
	if execute == nil || !absoluteCleanPath(config.Nginx.Binary) || !absoluteCleanPath(config.Nginx.ConfigPath) {
		return errors.New("invalid Nginx command configuration")
	}
	desired, err := RenderActiveMap(config, rules)
	if err != nil {
		return err
	}
	preflight, err := execute(ctx, config.Nginx.Binary, "-T", "-c", config.Nginx.ConfigPath)
	if err != nil {
		return fmt.Errorf("Nginx preflight failed: %w", err)
	}
	if err := ValidateNginxPreflight(preflight, config); err != nil {
		return err
	}
	root, err := os.OpenRoot(config.Nginx.ManagedDir)
	if err != nil {
		return err
	}
	defer root.Close()
	previous, err := readManagedFile(root, activeMapName, activeMapLimit)
	if err != nil {
		return err
	}
	if err := atomicfile.Replace(ctx, root, activeMapName, 0o644, desired); err != nil {
		return err
	}
	if _, err := execute(ctx, config.Nginx.Binary, "-t", "-c", config.Nginx.ConfigPath); err != nil {
		rollbackContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		rollbackErr := atomicfile.Replace(rollbackContext, root, activeMapName, 0o644, previous)
		cancel()
		if rollbackErr != nil {
			return &RollbackError{Apply: err, Rollback: rollbackErr}
		}
		return fmt.Errorf("Nginx validation failed; previous map restored: %w", err)
	}
	if _, err := execute(ctx, config.Nginx.Binary, "-s", "reload", "-c", config.Nginx.ConfigPath); err != nil {
		rollbackContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		rollbackErr := rollbackReload(rollbackContext, config, root, previous, execute)
		cancel()
		if rollbackErr != nil {
			return &RollbackError{Apply: err, Rollback: rollbackErr}
		}
		return fmt.Errorf("Nginx reload failed; previous map restored: %w", err)
	}
	return nil
}

func SetupManagedFiles(ctx context.Context, config Config, execute ExecuteCommand) (SetupResult, error) {
	if execute == nil || !absoluteCleanPath(config.Nginx.Binary) || !absoluteCleanPath(config.Nginx.ConfigPath) {
		return SetupResult{}, errors.New("invalid Nginx setup configuration")
	}
	httpInclude, serverInclude, err := RenderProtectionIncludes(config)
	if err != nil {
		return SetupResult{}, err
	}
	activeMap, err := RenderActiveMap(config, nil)
	if err != nil {
		return SetupResult{}, err
	}
	root, err := os.OpenRoot(config.Nginx.ManagedDir)
	if err != nil {
		return SetupResult{}, err
	}
	defer root.Close()
	previous, err := loadPreviousManagedFiles(root)
	if err != nil {
		return SetupResult{}, err
	}
	for _, file := range previous {
		if file.name == activeMapName && file.exists && !bytes.Equal(file.data, activeMap) {
			return SetupResult{}, errors.New("protect setup requires a canonically empty active map")
		}
	}
	desired := map[string][]byte{
		httpIncludeName:   httpInclude,
		serverIncludeName: serverInclude,
		activeMapName:     activeMap,
	}
	for _, name := range []string{httpIncludeName, serverIncludeName, activeMapName} {
		if err := atomicfile.Replace(ctx, root, name, 0o644, desired[name]); err != nil {
			rollbackContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			rollbackErr := restoreManagedFiles(rollbackContext, root, previous)
			cancel()
			if rollbackErr != nil {
				return SetupResult{}, &RollbackError{Apply: err, Rollback: rollbackErr}
			}
			return SetupResult{}, err
		}
	}
	preflight, err := execute(ctx, config.Nginx.Binary, "-T", "-c", config.Nginx.ConfigPath)
	if err != nil {
		return SetupResult{}, setupRollback(context.WithoutCancel(ctx), root, previous, err)
	}
	result, err := setupPreflightResult(preflight, config)
	if err != nil {
		return SetupResult{}, setupRollback(context.WithoutCancel(ctx), root, previous, err)
	}
	if _, err := execute(ctx, config.Nginx.Binary, "-t", "-c", config.Nginx.ConfigPath); err != nil {
		return SetupResult{}, setupRollback(context.WithoutCancel(ctx), root, previous, err)
	}
	if _, err := execute(ctx, config.Nginx.Binary, "-s", "reload", "-c", config.Nginx.ConfigPath); err != nil {
		rollbackContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		rollbackErr := restoreManagedFiles(rollbackContext, root, previous)
		if rollbackErr == nil {
			_, rollbackErr = execute(rollbackContext, config.Nginx.Binary, "-t", "-c", config.Nginx.ConfigPath)
		}
		if rollbackErr == nil {
			_, rollbackErr = execute(rollbackContext, config.Nginx.Binary, "-s", "reload", "-c", config.Nginx.ConfigPath)
		}
		cancel()
		if rollbackErr != nil {
			return SetupResult{}, &RollbackError{Apply: err, Rollback: rollbackErr}
		}
		return SetupResult{}, fmt.Errorf("Nginx setup reload failed; previous files restored: %w", err)
	}
	return result, nil
}

func ValidateNginxPreflight(output []byte, config Config) error {
	if len(output) > nginxPreflightLimit {
		return errors.New("Nginx preflight output exceeds 16 MiB")
	}
	for _, marker := range []string{HTTPMarker(config.Site), ServerMarker(config.Site), ActiveMarker(config.Site)} {
		if bytes.Count(output, []byte(marker)) != 1 {
			return errors.New("Nginx preflight must contain each managed marker exactly once")
		}
	}
	return nil
}

func rollbackReload(
	ctx context.Context,
	config Config,
	root *os.Root,
	previous []byte,
	execute ExecuteCommand,
) error {
	if err := atomicfile.Replace(ctx, root, activeMapName, 0o644, previous); err != nil {
		return err
	}
	if _, err := execute(ctx, config.Nginx.Binary, "-t", "-c", config.Nginx.ConfigPath); err != nil {
		return err
	}
	_, err := execute(ctx, config.Nginx.Binary, "-s", "reload", "-c", config.Nginx.ConfigPath)
	return err
}

func loadPreviousManagedFiles(root *os.Root) ([]previousManagedFile, error) {
	result := make([]previousManagedFile, 0, 3)
	for _, name := range []string{httpIncludeName, serverIncludeName, activeMapName} {
		data, err := readManagedFile(root, name, activeMapLimit)
		if errors.Is(err, os.ErrNotExist) {
			result = append(result, previousManagedFile{name: name})
			continue
		}
		if err != nil {
			return nil, err
		}
		result = append(result, previousManagedFile{name: name, data: data, exists: true})
	}
	return result, nil
}

func restoreManagedFiles(ctx context.Context, root *os.Root, previous []previousManagedFile) error {
	var result error
	for _, file := range previous {
		if file.exists {
			result = errors.Join(result, atomicfile.Replace(ctx, root, file.name, 0o644, file.data))
		} else {
			err := root.Remove(file.name)
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				result = errors.Join(result, err)
			}
		}
	}
	return errors.Join(result, syncManagedRoot(root))
}

func syncManagedRoot(root *os.Root) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}

func setupRollback(ctx context.Context, root *os.Root, previous []previousManagedFile, applyErr error) error {
	rollbackContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	rollbackErr := restoreManagedFiles(rollbackContext, root, previous)
	cancel()
	if rollbackErr != nil {
		return &RollbackError{Apply: applyErr, Rollback: rollbackErr}
	}
	return fmt.Errorf("Nginx setup failed; previous files restored: %w", applyErr)
}

func setupPreflightResult(output []byte, config Config) (SetupResult, error) {
	if len(output) > nginxPreflightLimit {
		return SetupResult{}, errors.New("Nginx preflight output exceeds 16 MiB")
	}
	counts := []int{
		bytes.Count(output, []byte(HTTPMarker(config.Site))),
		bytes.Count(output, []byte(ServerMarker(config.Site))),
		bytes.Count(output, []byte(ActiveMarker(config.Site))),
	}
	for _, count := range counts {
		if count > 1 {
			return SetupResult{}, errors.New("Nginx preflight contains duplicate managed markers")
		}
	}
	return SetupResult{
		HTTPIncluded: counts[0] == 1, ServerIncluded: counts[1] == 1, ActiveIncluded: counts[2] == 1,
	}, nil
}

func readManagedFile(root *os.Root, name string, limit int64) ([]byte, error) {
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > limit {
		return nil, errors.Join(err, errors.New("managed file is unsafe"))
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		_ = file.Close()
		return nil, errors.Join(err, errors.New("managed file changed while opening"))
	}
	data, readErr := io.ReadAll(io.LimitReader(file, limit+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || int64(len(data)) > limit {
		return nil, errors.Join(readErr, closeErr, errors.New("managed file exceeds limit"))
	}
	return data, nil
}

type limitedOutput struct {
	mutex     sync.Mutex
	limit     int
	data      []byte
	truncated bool
}

func (output *limitedOutput) Write(data []byte) (int, error) {
	output.mutex.Lock()
	defer output.mutex.Unlock()
	remaining := output.limit - len(output.data)
	if len(data) > remaining {
		output.truncated = true
	}
	if remaining > 0 {
		output.data = append(output.data, data[:min(remaining, len(data))]...)
	}
	return len(data), nil
}

func (output *limitedOutput) Truncated() bool {
	output.mutex.Lock()
	defer output.mutex.Unlock()
	return output.truncated
}

func (output *limitedOutput) Bytes() []byte {
	output.mutex.Lock()
	defer output.mutex.Unlock()
	return append([]byte(nil), output.data...)
}
