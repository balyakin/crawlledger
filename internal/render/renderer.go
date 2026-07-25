package render

import (
	"errors"
	"path/filepath"
	"sort"
	"strings"

	"github.com/balyakin/crawlledger/internal/catalog"
	"github.com/balyakin/crawlledger/internal/domain"
	"github.com/balyakin/crawlledger/internal/policy"
)

type Artifact struct {
	Name    string
	Content []byte
}

type Input struct {
	AnalysisID     string
	Simulation     domain.Simulation
	Policy         domain.Policy
	Catalog        *catalog.Catalog
	Acks           []string
	ObservedStates map[string]int64
}

type Renderer interface {
	Target() string
	Validate(Input) error
	Render(Input) ([]Artifact, error)
}

func New(target string) (Renderer, error) {
	switch target {
	case "nginx":
		return nginxRenderer{}, nil
	case "caddy":
		return caddyRenderer{}, nil
	default:
		return nil, errors.New("unsupported render target")
	}
}

func validateCommon(input Input) error {
	_, policyHash, err := policy.Canonical(input.Policy)
	if err != nil || input.Catalog == nil || len(input.Simulation.PolicyHash) != 64 ||
		input.Simulation.PolicyHash != policyHash ||
		input.AnalysisID != input.Simulation.AnalysisID ||
		input.Simulation.Status != domain.SimulationSafe && input.Simulation.Status != domain.SimulationRequiresAck {
		return errors.New("simulation is not renderable")
	}
	required := make([]string, 0)
	for _, risk := range input.Simulation.Risks {
		if risk.Acknowledgeable {
			required = append(required, risk.ID)
		}
	}
	sort.Strings(required)
	acks := append([]string(nil), input.Acks...)
	sort.Strings(acks)
	for index := 1; index < len(acks); index++ {
		if acks[index-1] == acks[index] {
			return errors.New("duplicate acknowledgement")
		}
	}
	if len(required) != len(acks) {
		return errors.New("exact risk acknowledgement set is required")
	}
	for index := range required {
		if required[index] != acks[index] {
			return errors.New("unknown, extra or missing risk acknowledgement")
		}
	}
	return nil
}

func validateArtifacts(artifacts []Artifact) error {
	total := 0
	names := make(map[string]struct{}, len(artifacts))
	for _, artifact := range artifacts {
		if artifact.Name == "" || filepath.Base(artifact.Name) != artifact.Name ||
			strings.ContainsAny(artifact.Name, `/\`) {
			return errors.New("invalid artifact name")
		}
		if _, exists := names[artifact.Name]; exists {
			return errors.New("duplicate artifact name")
		}
		names[artifact.Name] = struct{}{}
		total += len(artifact.Content)
	}
	if total > 4<<20 {
		return errors.New("render artifacts exceed 4 MiB")
	}
	sort.Slice(artifacts, func(i, j int) bool { return artifacts[i].Name < artifacts[j].Name })
	return nil
}
