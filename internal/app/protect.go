package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"time"

	"github.com/balyakin/crawlledger/internal/apperr"
	"github.com/balyakin/crawlledger/internal/input"
	"github.com/balyakin/crawlledger/internal/normalize"
	"github.com/balyakin/crawlledger/internal/parser"
	"github.com/balyakin/crawlledger/internal/protect"
)

type followedRecord struct {
	line []byte
	err  error
}

type applyProtectionState func(context.Context, string, string, protect.State) error

func (s *Service) ProtectRun(
	ctx context.Context,
	request ProtectRunRequest,
) (ProtectRunResult, error) {
	loaded, baseline, workspace, follower, err := prepareProtectionRun(ctx, request.ConfigPath)
	if err != nil {
		return ProtectRunResult{}, err
	}
	defer workspace.Close()
	followerStarted := false
	defer func() {
		if !followerStarted {
			_ = follower.Close()
		}
	}()
	result := ProtectRunResult{
		Mode: "dry-run", CompleteMinutes: baseline.CompleteMinutes, BaselineEligible: baseline.Eligible,
	}
	if !baseline.Eligible {
		s.logger.Warn(
			"protection baseline is not eligible for live apply",
			"event", "protect_detection_suspended",
			"site", loaded.Config.Site,
			"reasons", baseline.IneligibilityReasons,
		)
	}
	state := protect.EmptyState(loaded.Config.Site, loaded.SHA256, &baseline.ManifestSHA256)
	var coordinatorLock *protect.FileLock
	executable := ""
	if request.Apply {
		result.Mode = "apply"
		if !baseline.Eligible {
			return result, apperr.New(
				apperr.CodeUnsafePolicy,
				"protect run",
				"historical baseline is not eligible for live protection",
				nil,
			)
		}
		executable, err = protectionExecutable()
		if err != nil {
			return result, protectError("protect run", "cannot resolve executable", err)
		}
		if _, err := protect.ValidateLiveSecurity(loaded, executable); err != nil {
			return result, protectError("protect run", "live security validation failed", err)
		}
		coordinatorLock, err = protect.AcquireCoordinatorLock(loaded.Config)
		if err != nil {
			return result, protectError("protect run", "another protection coordinator is active", err)
		}
		defer coordinatorLock.Close()
		state, err = reconcileLiveState(ctx, loaded, baseline, executable)
		if err != nil {
			return result, protectError("protect run", "cannot reconcile live protection", err)
		}
	}
	key, err := normalize.GenerateKey()
	if err != nil {
		return result, protectError("protect run", "cannot generate in-memory HMAC key", err)
	}
	normalizer := normalize.New(key)
	detector, err := protect.NewDetector(loaded.Config, loaded.SHA256, baseline, state)
	if err != nil {
		return result, protectError("protect run", "cannot initialize detector", err)
	}
	if request.Apply {
		detector.MarkApplied(time.Now().UTC().UnixMicro())
	}
	followerStarted = true
	err = s.runProtectionLoop(ctx, loaded, detector, normalizer, follower, request.Apply, executable)
	if errors.Is(err, context.Canceled) {
		if request.Apply {
			clearContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 50*time.Second)
			clearErr := clearLiveState(clearContext, loaded, executable)
			cancel()
			if clearErr != nil {
				return result, protectError(
					"protect run",
					"graceful stop failed; temporary Nginx rules may still be active",
					clearErr,
				)
			}
		}
		return result, nil
	}
	if err != nil {
		return result, protectError("protect run", "protection watcher stopped", err)
	}
	return result, nil
}

func (s *Service) ProtectSetup(ctx context.Context, request ProtectSetupRequest) (ProtectSetupResult, error) {
	loaded, err := protect.LoadConfig(request.ConfigPath)
	if err != nil {
		return ProtectSetupResult{}, apperr.New(apperr.CodeConfig, "protect setup", "invalid protection config", err)
	}
	if err := protect.RequireMutationPlatform(); err != nil {
		return ProtectSetupResult{}, protectError("protect setup", err.Error(), err)
	}
	executable, err := protectionExecutable()
	if err != nil {
		return ProtectSetupResult{}, protectError("protect setup", "cannot resolve executable", err)
	}
	identity, err := protect.ValidateSetupSecurity(loaded, executable)
	if err != nil {
		return ProtectSetupResult{}, protectError("protect setup", "setup security validation failed", err)
	}
	serviceUser, err := user.LookupId(fmt.Sprint(identity.UID))
	if err != nil {
		return ProtectSetupResult{}, protectError("protect setup", "cannot resolve service user", err)
	}
	serviceGroup, err := user.LookupGroupId(fmt.Sprint(identity.GID))
	if err != nil {
		return ProtectSetupResult{}, protectError("protect setup", "cannot resolve service group", err)
	}
	stateLock, applyLock, provisionedIdentity, err := protect.ProvisionSetupLocks(loaded.Config)
	if err != nil {
		return ProtectSetupResult{}, protectError("protect setup", "cannot provision protection locks", err)
	}
	defer stateLock.Close()
	defer applyLock.Close()
	if provisionedIdentity != identity {
		return ProtectSetupResult{}, protectError("protect setup", "state directory identity changed", nil)
	}
	state, exists, err := protect.ReadState(loaded.Config.Runtime.StateFile)
	if err != nil {
		return ProtectSetupResult{}, protectError("protect setup", "state is corrupt; run protect clear", err)
	}
	if exists && len(state.Rules) != 0 {
		return ProtectSetupResult{}, protectError("protect setup", "temporary rules must be cleared first", nil)
	}
	executor := protect.CommandExecutor{Timeout: 10 * time.Second, OutputLimit: 16 << 20}
	setup, err := protect.SetupManagedFiles(ctx, loaded.Config, executor.Run)
	if err != nil {
		return ProtectSetupResult{}, protectError("protect setup", "cannot install managed Nginx files", err)
	}
	return ProtectSetupResult{
		HTTPInclude:   filepath.Join(loaded.Config.Nginx.ManagedDir, "crawlledger-http.conf"),
		ServerInclude: filepath.Join(loaded.Config.Nginx.ManagedDir, "crawlledger-server.conf"),
		Executable:    executable,
		ConfigPath:    loaded.Path,
		ServiceUser:   serviceUser.Username, ServiceGroup: serviceGroup.Name,
		IncludesActive: setup.HTTPIncluded && setup.ServerIncluded && setup.ActiveIncluded,
	}, nil
}

func (s *Service) ProtectClear(ctx context.Context, request ProtectClearRequest) error {
	loaded, err := protect.LoadConfig(request.ConfigPath)
	if err != nil {
		return apperr.New(apperr.CodeConfig, "protect clear", "invalid protection config", err)
	}
	if err := protect.RequireMutationPlatform(); err != nil {
		return protectError("protect clear", err.Error(), err)
	}
	executable, err := protectionExecutable()
	if err != nil {
		return protectError("protect clear", "cannot resolve executable", err)
	}
	if _, err := protect.ValidateLiveSecurity(loaded, executable); err != nil {
		return protectError("protect clear", "clear security validation failed", err)
	}
	lock, err := protect.AcquireCoordinatorLock(loaded.Config)
	if err != nil {
		return protectError("protect clear", "watcher is active", err)
	}
	defer lock.Close()
	if err := clearLiveState(ctx, loaded, executable); err != nil {
		return protectError("protect clear", "cannot clear temporary Nginx rules", err)
	}
	return nil
}

func (s *Service) ProtectApply(ctx context.Context, request ProtectApplyRequest) error {
	loaded, err := protect.LoadConfig(request.ConfigPath)
	if err != nil {
		return apperr.New(apperr.CodeConfig, "protect apply", "invalid protection config", err)
	}
	if err := protect.RequireMutationPlatform(); err != nil {
		return protectError("protect apply", err.Error(), err)
	}
	executable, err := protectionExecutable()
	if err != nil {
		return protectError("protect apply", "cannot resolve executable", err)
	}
	if _, err := protect.ValidateApplySecurity(loaded, executable); err != nil {
		return protectError("protect apply", "apply security validation failed", err)
	}
	if err := protect.ProbeCoordinatorLock(loaded.Config); err != nil {
		return protectError("protect apply", "coordinator lock check failed", err)
	}
	lock, err := protect.AcquireApplyLock(loaded.Config)
	if err != nil {
		return protectError("protect apply", "another apply is active", err)
	}
	defer lock.Close()
	if err := protect.ProbeCoordinatorLock(loaded.Config); err != nil {
		return protectError("protect apply", "coordinator lock changed", err)
	}
	payload, err := io.ReadAll(io.LimitReader(s.stdin, 64<<10+1))
	if err != nil || len(payload) > 64<<10 {
		return protectError("protect apply", "invalid bounded apply payload", err)
	}
	state, exists, err := protect.ReadState(loaded.Config.Runtime.StateFile)
	if err != nil {
		return protectError("protect apply", "cannot read desired state", err)
	}
	if !exists {
		state = protect.EmptyState(loaded.Config.Site, loaded.SHA256, nil)
	}
	rules, err := protect.ValidateApplyRequest(loaded.Config, loaded.SHA256, state, payload)
	if err != nil {
		return protectError("protect apply", "apply payload does not match desired state", err)
	}
	executor := protect.CommandExecutor{Timeout: 10 * time.Second, OutputLimit: 16 << 20}
	if err := protect.ApplyActiveMap(ctx, loaded.Config, rules, executor.Run); err != nil {
		return protectError("protect apply", "cannot apply desired Nginx map", err)
	}
	return nil
}

func prepareProtectionRun(
	ctx context.Context,
	configPath string,
) (protect.LoadedConfig, protect.Baseline, *verifiedWorkspace, *protect.Follower, error) {
	loaded, err := protect.LoadConfig(configPath)
	if err != nil {
		return protect.LoadedConfig{}, protect.Baseline{}, nil, nil,
			apperr.New(apperr.CodeConfig, "protect run", "invalid protection config", err)
	}
	workspace, err := openWorkspace(ctx, loaded.Config.BaselineWorkspace)
	if err != nil {
		return protect.LoadedConfig{}, protect.Baseline{}, nil, nil,
			apperr.New(apperr.CodeInput, "protect run", "invalid baseline workspace", err)
	}
	history, err := workspace.store.LoadProtectionHistory(ctx)
	if err != nil {
		_ = workspace.Close()
		return protect.LoadedConfig{}, protect.Baseline{}, nil, nil,
			apperr.New(apperr.CodeStorage, "protect run", "cannot load baseline history", err)
	}
	baseline, err := protect.BuildBaseline(history, workspace.manifestHash)
	if err != nil {
		_ = workspace.Close()
		return protect.LoadedConfig{}, protect.Baseline{}, nil, nil,
			apperr.New(apperr.CodeInput, "protect run", "cannot build protection baseline", err)
	}
	follower, err := protect.OpenFollower(loaded.Config.LogPath, loaded.Config.Runtime.MaxLogLineBytes)
	if err != nil {
		_ = workspace.Close()
		return protect.LoadedConfig{}, protect.Baseline{}, nil, nil,
			apperr.New(apperr.CodeInput, "protect run", "cannot open protection log", err)
	}
	return loaded, baseline, workspace, follower, nil
}

func reconcileLiveState(
	ctx context.Context,
	loaded protect.LoadedConfig,
	baseline protect.Baseline,
	executable string,
) (protect.State, error) {
	return reconcileLiveStateWith(ctx, loaded, baseline, executable, protect.InvokePrivilegedApply)
}

func reconcileLiveStateWith(
	ctx context.Context,
	loaded protect.LoadedConfig,
	baseline protect.Baseline,
	executable string,
	applyState applyProtectionState,
) (protect.State, error) {
	if applyState == nil {
		return protect.State{}, errors.New("apply callback is required")
	}
	state, exists, err := protect.ReadState(loaded.Config.Runtime.StateFile)
	if err != nil {
		return protect.State{}, err
	}
	baselineDigest := baseline.ManifestSHA256
	empty := protect.EmptyState(loaded.Config.Site, loaded.SHA256, &baselineDigest)
	if !exists {
		state = empty
		if err := protect.WriteState(ctx, loaded.Config.Runtime.StateFile, state); err != nil {
			return protect.State{}, err
		}
	} else if state.Site != loaded.Config.Site || state.ConfigSHA256 != loaded.SHA256 ||
		state.BaselineManifestSHA256 == nil || *state.BaselineManifestSHA256 != baseline.ManifestSHA256 {
		state = empty
		if err := protect.WriteState(ctx, loaded.Config.Runtime.StateFile, state); err != nil {
			return protect.State{}, err
		}
	}
	nowUS := time.Now().UTC().UnixMicro()
	kept := state.Rules[:0]
	for _, rule := range state.Rules {
		if rule.ExpiresAtUS > nowUS {
			kept = append(kept, rule)
		}
	}
	if len(kept) != len(state.Rules) {
		state.Rules = kept
		if err := protect.WriteState(ctx, loaded.Config.Runtime.StateFile, state); err != nil {
			return protect.State{}, err
		}
	}
	if err := applyState(ctx, executable, loaded.Path, state); err != nil {
		return protect.State{}, err
	}
	return state, nil
}

func (s *Service) runProtectionLoop(
	ctx context.Context,
	loaded protect.LoadedConfig,
	detector *protect.Detector,
	normalizer *normalize.Normalizer,
	follower *protect.Follower,
	apply bool,
	executable string,
) error {
	runContext, cancel := context.WithCancel(ctx)
	defer cancel()
	records := make(chan followedRecord)
	followDone := make(chan error, 1)
	go func() {
		followDone <- follower.Follow(runContext, func(line []byte, lineErr error) error {
			record := followedRecord{line: append([]byte(nil), line...), err: lineErr}
			select {
			case records <- record:
				return nil
			case <-runContext.Done():
				return runContext.Err()
			}
		})
	}()
	interval := time.Duration(loaded.Config.Detection.EvaluationIntervalSeconds) * time.Second
	evaluation := time.Now().UTC().Truncate(interval).Add(interval)
	timer := time.NewTimer(time.Until(evaluation))
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-followDone:
			return err
		case record := <-records:
			s.observeProtectionRecord(detector, normalizer, record)
		case <-timer.C:
			decision, err := detector.Evaluate(evaluation.UnixMicro())
			if err != nil {
				return err
			}
			if err := s.handleProtectionDecision(ctx, loaded, detector, decision, apply, executable, evaluation); err != nil {
				return err
			}
			now := time.Now().UTC()
			for !evaluation.After(now) {
				evaluation = evaluation.Add(interval)
			}
			timer.Reset(time.Until(evaluation))
		}
	}
}

func (s *Service) observeProtectionRecord(
	detector *protect.Detector,
	normalizer *normalize.Normalizer,
	record followedRecord,
) {
	receiptUS := time.Now().UTC().UnixMicro()
	if record.err != nil {
		detector.ObserveError(receiptUS, parser.RecordContentError, errors.Is(record.err, input.ErrLineTooLong))
		return
	}
	parsed, class, err := parser.ParseNginxProtection(record.line)
	if err != nil {
		detector.ObserveError(receiptUS, class, len(record.line) != 0)
		return
	}
	event, canonical, err := normalizer.NormalizeProtection(*parsed.Raw, normalize.Facts{})
	if err != nil {
		detector.ObserveError(receiptUS, parser.RecordContentError, true)
		return
	}
	detector.Observe(protect.ProtectionRecord{
		Event: event, CanonicalPath: canonical, NginxURI: parsed.NginxURI, LimitReqStatus: parsed.LimitReqStatus,
	}, receiptUS)
}

func (s *Service) handleProtectionDecision(
	ctx context.Context,
	loaded protect.LoadedConfig,
	detector *protect.Detector,
	decision protect.Decision,
	apply bool,
	executable string,
	evaluation time.Time,
) error {
	if apply && decision.StateChanged {
		if err := protect.WriteState(ctx, loaded.Config.Runtime.StateFile, decision.State); err != nil {
			return err
		}
	}
	applySucceeded := false
	applyStatus := "unchanged"
	if decision.ApplyRequired && !decision.ApplyNow {
		applyStatus = "coalesced"
	}
	if decision.ApplyNow {
		if apply {
			applyStatus = "failed"
			err := protect.InvokePrivilegedApply(ctx, executable, loaded.Path, decision.State)
			if err != nil {
				s.logger.Error("protection apply failed", "event", "protect_apply_failed", "site", loaded.Config.Site)
				if protect.IsRollbackFailure(err) {
					s.logger.Error("protection rollback failed", "event", "protect_rollback_failed", "site", loaded.Config.Site)
					return err
				}
			} else {
				applySucceeded = true
				applyStatus = "applied"
			}
		} else {
			applySucceeded = true
			applyStatus = "dry-run"
		}
		if applySucceeded {
			detector.MarkApplied(evaluation.UnixMicro())
		}
	}
	for _, event := range decision.Events {
		if apply && event.Kind == "protect_activated" && !applySucceeded {
			continue
		}
		s.logger.Info(
			"protection event",
			"event", event.Kind,
			"site", loaded.Config.Site,
			"detector", event.Detector,
			"method", event.Method,
			"path_prefix", event.PathPrefix,
			"requests", event.Requests,
			"site_requests", event.SiteRequests,
			"distinct_clients", event.DistinctClients,
			"upstream_samples", event.UpstreamSamples,
			"upstream_duration_us", event.UpstreamDurationUS,
			"baseline_requests", event.BaselineRequests,
			"baseline_upstream_us", event.BaselineUpstreamUS,
			"request_threshold", event.RequestThreshold,
			"upstream_threshold", event.UpstreamThreshold,
			"expires_at_us", event.ExpiresAtUS,
			"apply_status", applyStatus,
			"max_event_lag_us", decision.MaxEventLagUS,
			"rejected_record_content", decision.RejectedRecords.RecordContent,
			"rejected_sensor_structure", decision.RejectedRecords.SensorStructure,
			"rejected_stale", decision.RejectedRecords.Stale,
			"rejected_future", decision.RejectedRecords.Future,
			"rejected_invalid_status", decision.RejectedRecords.InvalidStatus,
			"rejected_counter_overflow", decision.RejectedRecords.CounterOverflow,
		)
	}
	return nil
}

func clearLiveState(ctx context.Context, loaded protect.LoadedConfig, executable string) error {
	state := protect.EmptyState(loaded.Config.Site, loaded.SHA256, nil)
	if err := protect.WriteState(ctx, loaded.Config.Runtime.StateFile, state); err != nil {
		return err
	}
	return protect.InvokePrivilegedApply(ctx, executable, loaded.Path, state)
}

func protectionExecutable() (string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", err
	}
	executable, err = filepath.Abs(executable)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(executable)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.Join(err, errors.New("executable must be a regular non-symlink file"))
	}
	return executable, nil
}

func protectError(operation, message string, err error) error {
	return apperr.New(apperr.CodeInternal, operation, message, err)
}
