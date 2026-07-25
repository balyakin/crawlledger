package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"path/filepath"
	"sort"

	"github.com/balyakin/crawlledger/internal/apperr"
	"github.com/balyakin/crawlledger/internal/atomicfile"
	"github.com/balyakin/crawlledger/internal/catalog"
	"github.com/balyakin/crawlledger/internal/domain"
	"github.com/balyakin/crawlledger/internal/policy"
	"github.com/balyakin/crawlledger/internal/render"
	"github.com/balyakin/crawlledger/internal/report"
)

type RenderZone struct {
	Profile        string `json:"profile"`
	ObservedStates int64  `json:"observed_states"`
	BytesPerState  int64  `json:"bytes_per_state"`
	Headroom       int64  `json:"headroom"`
	ZoneMiB        int64  `json:"zone_mib"`
	Warning        string `json:"warning"`
}

type RenderManifest struct {
	SchemaVersion           int               `json:"schema_version"`
	ToolVersion             string            `json:"tool_version"`
	Target                  string            `json:"target"`
	TestedVersion           string            `json:"tested_version"`
	AnalysisID              string            `json:"analysis_id"`
	RunID                   string            `json:"run_id"`
	PolicyHash              string            `json:"policy_hash"`
	SimulationSHA256        string            `json:"simulation_sha256"`
	WorkspaceManifestSHA256 string            `json:"workspace_manifest_sha256"`
	AcknowledgedRisks       []string          `json:"acknowledged_risks"`
	Files                   []report.Artifact `json:"files"`
	NginxZones              []RenderZone      `json:"nginx_zones"`
	Instructions            []string          `json:"instructions"`
	NotApplied              bool              `json:"not_applied"`
}

func (s *Service) Render(ctx context.Context, request RenderRequest) (result RenderResult, returnErr error) {
	if request.Workspace == "" || request.Policy == "" || request.Simulation == "" ||
		request.OutputDir == "" || request.Target != "nginx" && request.Target != "caddy" {
		return result, apperr.New(apperr.CodeUsage, "policy render", "all flags and a supported target are required", nil)
	}
	if err := ensureOutsideWorkspace(request.OutputDir, request.Workspace); err != nil {
		return result, apperr.New(apperr.CodeUsage, "policy render", err.Error(), err)
	}
	workspace, err := openWorkspace(ctx, request.Workspace)
	if err != nil {
		return result, apperr.New(apperr.CodeUnsafePolicy, "policy render", "workspace integrity check failed", err)
	}
	defer func() {
		if closeErr := workspace.Close(); returnErr == nil && closeErr != nil {
			returnErr = apperr.New(apperr.CodeStorage, "policy render", "cannot close workspace", closeErr)
		}
	}()
	catalogValue, err := catalog.LoadEmbedded()
	if err != nil {
		return result, apperr.New(apperr.CodeInternal, "policy render", "cannot load catalog", err)
	}
	value, err := policy.Load(request.Policy)
	if err != nil {
		return result, apperr.New(apperr.CodeUnsafePolicy, "policy render", "policy proof is invalid", err)
	}
	if err := policy.Validate(value, catalogValue); err != nil {
		return result, apperr.New(apperr.CodeUnsafePolicy, "policy render", "policy proof is invalid", err)
	}
	_, policyHash, err := policy.Canonical(value)
	if err != nil {
		return result, apperr.New(apperr.CodeInternal, "policy render", "cannot canonicalize policy", err)
	}
	sidecar, sidecarBytes, err := policy.LoadSimulation(request.Simulation)
	if err != nil {
		return result, apperr.New(apperr.CodeUnsafePolicy, "policy render", "simulation integrity check failed", err)
	}
	canonicalSidecar, err := policy.CanonicalSimulation(sidecar)
	if err != nil || !bytes.Equal(canonicalSidecar, sidecarBytes) {
		return result, apperr.New(apperr.CodeUnsafePolicy, "policy render", "simulation integrity check failed", err)
	}
	recomputed, observedStates, err := runSimulation(ctx, workspace, value, policyHash)
	if err != nil {
		return result, apperr.New(apperr.CodeStorage, "policy render", "cannot repeat simulation", err)
	}
	recomputedBytes, err := policy.CanonicalSimulation(recomputed)
	if err != nil || !bytes.Equal(recomputedBytes, sidecarBytes) ||
		sidecar.AnalysisID != workspace.manifest.AnalysisID || sidecar.PolicyHash != policyHash ||
		sidecar.RunID != recomputed.RunID {
		return result, apperr.New(apperr.CodeUnsafePolicy, "policy render", "simulation does not match workspace and policy", err)
	}
	if err := validateAcknowledgements(sidecar, request.Acks); err != nil {
		return result, err
	}
	renderer, err := render.New(request.Target)
	if err != nil {
		return result, apperr.New(apperr.CodeUsage, "policy render", "unsupported target", err)
	}
	renderInput := render.Input{
		AnalysisID: workspace.manifest.AnalysisID, Simulation: recomputed, Policy: value,
		Catalog: catalogValue, Acks: request.Acks, ObservedStates: observedStates,
	}
	artifacts, err := renderer.Render(renderInput)
	if err != nil {
		return result, apperr.New(apperr.CodeUnsupportedPolicy, "policy render", "policy cannot be rendered for target", err)
	}
	output, err := createDirectory(request.OutputDir)
	if err != nil {
		return result, apperr.New(apperr.CodeOutput, "policy render", "cannot create output directory", err)
	}
	defer func() {
		if closeErr := output.Close(); returnErr == nil && closeErr != nil {
			returnErr = apperr.New(apperr.CodeOutput, "policy render", "cannot close output directory", closeErr)
		}
	}()
	output.keep = true
	names := make([]string, 0, len(artifacts))
	for _, artifact := range artifacts {
		warnings, err := atomicfile.WriteNew(ctx, output.root, artifact.Name, 0o600, func(writer io.Writer) error {
			_, err := writer.Write(artifact.Content)
			return err
		})
		if err != nil {
			return result, apperr.New(apperr.CodeOutput, "policy render", "cannot publish target artifact", err)
		}
		logWarnings(s.logger, warnings)
		names = append(names, artifact.Name)
	}
	files, err := report.InspectArtifacts(ctx, output.root, names...)
	if err != nil {
		return result, apperr.New(apperr.CodeOutput, "policy render", "cannot hash target artifacts", err)
	}
	sidecarHash := sha256.Sum256(sidecarBytes)
	acks := append([]string(nil), request.Acks...)
	sort.Strings(acks)
	manifest := RenderManifest{
		SchemaVersion: 1, ToolVersion: s.build.Version, Target: request.Target,
		TestedVersion: testedVersion(request.Target), AnalysisID: sidecar.AnalysisID,
		RunID: sidecar.RunID, PolicyHash: policyHash,
		SimulationSHA256:        hex.EncodeToString(sidecarHash[:]),
		WorkspaceManifestSHA256: workspace.manifestHash,
		AcknowledgedRisks:       acks, Files: files, NginxZones: renderZones(value, observedStates),
		Instructions: renderInstructions(request.Target), NotApplied: true,
	}
	warnings, err := atomicfile.WriteNew(ctx, output.root, "MANIFEST.json", 0o600, func(writer io.Writer) error {
		encoder := json.NewEncoder(writer)
		encoder.SetEscapeHTML(true)
		return encoder.Encode(manifest)
	})
	if err != nil {
		return result, apperr.New(apperr.CodeOutput, "policy render", "cannot publish render manifest", err)
	}
	logWarnings(s.logger, warnings)
	return RenderResult{Target: request.Target, Output: filepath.Clean(request.OutputDir), Files: len(files)}, nil
}

func validateAcknowledgements(simulation domain.Simulation, supplied []string) error {
	required := make(map[string]struct{})
	for _, risk := range simulation.Risks {
		if risk.Acknowledgeable {
			required[risk.ID] = struct{}{}
		}
	}
	seen := make(map[string]struct{}, len(supplied))
	for _, ack := range supplied {
		if _, duplicate := seen[ack]; duplicate {
			return apperr.New(apperr.CodeUsage, "policy render", "duplicate acknowledgement", nil)
		}
		seen[ack] = struct{}{}
		if _, known := required[ack]; !known {
			return apperr.New(apperr.CodeUsage, "policy render", "unknown or extra acknowledgement", nil)
		}
	}
	if simulation.Status == domain.SimulationBlocked || simulation.Status == domain.SimulationAnalysis {
		return apperr.New(apperr.CodeUnsafePolicy, "policy render", "simulation contains a non-acknowledgeable blocker", nil)
	}
	if len(seen) != len(required) {
		return apperr.New(apperr.CodeUnsafePolicy, "policy render", "required risk acknowledgement is missing", nil)
	}
	return nil
}

func testedVersion(target string) string {
	if target == "nginx" {
		return "nginx 1.30.4"
	}
	return "caddy 2.11.4"
}

func renderZones(value domain.Policy, states map[string]int64) []RenderZone {
	profiles := make(map[string]struct{})
	for _, rule := range value.Rules {
		if rule.Action.Kind == domain.ActionRateLimit {
			profiles[*rule.Action.RateProfile] = struct{}{}
		}
	}
	names := make([]string, 0, len(profiles))
	for profile := range profiles {
		names = append(names, profile)
	}
	sort.Strings(names)
	result := make([]RenderZone, 0, len(names))
	for _, profile := range names {
		zone := (states[profile]*512 + (1 << 20) - 1) / (1 << 20)
		if zone < 1 {
			zone = 1
		}
		result = append(result, RenderZone{
			Profile: profile, ObservedStates: states[profile], BytesPerState: 256,
			Headroom: 2, ZoneMiB: zone,
			Warning: "Zone exhaustion depends on future client and crawler cardinality.",
		})
	}
	return result
}

func renderInstructions(target string) []string {
	if target == "nginx" {
		return []string{
			"Include crawlledger-http.conf inside http {}.",
			"Include crawlledger-server.conf inside the audited server {} before the content handler.",
			"Create a backup of the active configuration.",
			"Run nginx -t.",
			"Reload Nginx manually.",
			"Check 403, 429 and access logs.",
			"Roll back manually if validation fails.",
		}
	}
	return []string{
		"Import Caddyfile.crawlledger before reverse_proxy.",
		"Create a backup of the active configuration.",
		"Run caddy adapt --config Caddyfile --adapter caddyfile --validate.",
		"Run caddy validate --config Caddyfile.",
		"Reload Caddy manually.",
		"Roll back manually if validation fails.",
	}
}
