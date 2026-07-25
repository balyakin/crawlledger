package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"

	"github.com/balyakin/crawlledger/internal/apperr"
	"github.com/balyakin/crawlledger/internal/catalog"
	"github.com/balyakin/crawlledger/internal/config"
	"github.com/balyakin/crawlledger/internal/cost"
	"github.com/balyakin/crawlledger/internal/domain"
	"github.com/balyakin/crawlledger/internal/policy"
)

func (s *Service) Simulate(ctx context.Context, request SimulateRequest) (result SimulateResult, returnErr error) {
	if request.Workspace == "" || request.Policy == "" || request.Output == "" {
		return result, apperr.New(apperr.CodeUsage, "policy simulate", "workspace, policy and output are required", nil)
	}
	if err := ensureOutsideWorkspace(request.Output, request.Workspace); err != nil {
		return result, apperr.New(apperr.CodeUsage, "policy simulate", err.Error(), err)
	}
	workspace, err := openWorkspace(ctx, request.Workspace)
	if err != nil {
		return result, apperr.New(apperr.CodeUnsafePolicy, "policy simulate", "workspace integrity check failed", err)
	}
	defer func() {
		if closeErr := workspace.Close(); returnErr == nil && closeErr != nil {
			returnErr = apperr.New(apperr.CodeStorage, "policy simulate", "cannot close workspace", closeErr)
		}
	}()
	catalogValue, err := catalog.LoadEmbedded()
	if err != nil {
		return result, apperr.New(apperr.CodeInternal, "policy simulate", "cannot load catalog", err)
	}
	value, err := policy.Load(request.Policy)
	if err != nil {
		return result, apperr.New(apperr.CodeConfig, "policy simulate", "invalid policy", err)
	}
	if err := policy.Validate(value, catalogValue); err != nil {
		return result, apperr.New(apperr.CodeConfig, "policy simulate", "invalid policy", err)
	}
	_, policyHash, err := policy.Canonical(value)
	if err != nil {
		return result, apperr.New(apperr.CodeInternal, "policy simulate", "cannot canonicalize policy", err)
	}
	simulation, _, err := runSimulation(ctx, workspace, value, policyHash)
	if err != nil {
		return result, apperr.New(apperr.CodeStorage, "policy simulate", "cannot simulate policy", err)
	}
	data, err := policy.CanonicalSimulation(simulation)
	if err != nil || len(data) > 8<<20 {
		return result, apperr.New(apperr.CodeInternal, "policy simulate", "simulation contract exceeded", err)
	}
	warnings, err := writeNewPath(ctx, request.Output, 0o600, func(writer io.Writer) error {
		_, err := writer.Write(data)
		return err
	})
	if err != nil {
		return result, apperr.New(apperr.CodeOutput, "policy simulate", "cannot publish simulation", err)
	}
	logWarnings(s.logger, warnings)
	return SimulateResult{
		RunID: simulation.RunID, Status: string(simulation.Status), Risks: len(simulation.Risks),
		Output: request.Output,
	}, nil
}

func runSimulation(
	ctx context.Context,
	workspace *verifiedWorkspace,
	value domain.Policy,
	policyHash string,
) (domain.Simulation, map[string]int64, error) {
	simulator := policy.NewSimulator(value, workspace.manifest.AnalysisID, policyHash)
	routes, _, _, err := workspace.store.LoadOverflowCounts(ctx)
	if err != nil {
		return domain.Simulation{}, nil, err
	}
	simulator.SetRouteOverflow(routes)
	if err := workspace.store.VisitTrafficCells(ctx, simulator.Add); err != nil {
		return domain.Simulation{}, nil, err
	}
	if err := workspace.store.VisitSubjectStates(ctx, func(
		name *string,
		category *domain.TrafficClass,
	) error {
		return simulator.AddSubjectState(name, category)
	}); err != nil {
		return domain.Simulation{}, nil, err
	}
	rate, err := workspace.store.LoadRateImpacts(ctx)
	if err != nil {
		return domain.Simulation{}, nil, err
	}
	simulation, err := simulator.Finish(rate)
	if err != nil {
		return domain.Simulation{}, nil, err
	}
	if !policy.Conserves(simulation) {
		return domain.Simulation{}, nil, errors.New("simulation conservation failed")
	}
	metadata, err := workspace.store.LoadCostMetadata(ctx)
	if err != nil {
		return domain.Simulation{}, nil, err
	}
	if err := applyAvoidedCosts(&simulation, metadata); err != nil {
		return domain.Simulation{}, nil, err
	}
	return simulation, simulator.ObservedStates(), nil
}

func applyAvoidedCosts(simulation *domain.Simulation, metadata domain.CostMetadata) error {
	if metadata.FirstEventUS == nil || metadata.LastEventUS == nil {
		return nil
	}
	var cfg config.Config
	if err := json.Unmarshal([]byte(metadata.ConfigJSON), &cfg); err != nil {
		return err
	}
	coverage := int64(0)
	if metadata.Accepted > 0 {
		coverage = domain.RatioPPM(metadata.UpstreamDurationSamples, metadata.Accepted)
	}
	input := cost.AvoidedInputs{
		FirstEventUS: *metadata.FirstEventUS, LastEventUS: *metadata.LastEventUS,
		TotalUpstreamUS: metadata.UpstreamUS, UpstreamCoveragePPM: coverage,
		MonthlyHostingKopecks: cfg.Costs.MonthlyHostingKopecks,
		EgressKopecksPerGiB:   cfg.Costs.EgressKopecksPerGiB,
	}
	input.BytesAvoided, input.UpstreamUSAvoided = simulation.Totals.BytesAvoided, simulation.Totals.UpstreamUSAvoided
	total, err := cost.CalculateAvoided(input)
	if err != nil {
		return err
	}
	simulation.Totals.AllocatedCostAvoidedKopecks = total
	for index := range simulation.RuleImpacts {
		impact := &simulation.RuleImpacts[index]
		if impact.Action != domain.ActionDeny && impact.Action != domain.ActionRateLimit {
			continue
		}
		input.BytesAvoided, input.UpstreamUSAvoided = impact.BytesAvoided, impact.UpstreamUSAvoided
		impact.AllocatedCostAvoidedKopecks, err = cost.CalculateAvoided(input)
		if err != nil {
			return err
		}
	}
	return nil
}
