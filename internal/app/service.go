package app

import (
	"io"
	"log/slog"

	"github.com/balyakin/crawlledger/internal/parser"
	"github.com/balyakin/crawlledger/internal/version"
)

type Service struct {
	stdin  io.Reader
	logger *slog.Logger
	build  version.Info
}

func New(stdin io.Reader, logger *slog.Logger, build version.Info) *Service {
	return &Service{stdin: stdin, logger: logger, build: build}
}

type AnalyzeRequest struct {
	Inputs      []string
	Format      parser.Format
	OutputDir   string
	ConfigPath  string
	RobotsPath  string
	KeyFilePath string
}

type AnalyzeResult struct {
	AnalysisID string
	Accepted   int64
	Rejected   int64
	ReportJSON string
	ReportHTML string
}

type SanitizeRequest struct {
	Inputs      []string
	Format      parser.Format
	OutputDir   string
	RobotsPath  string
	KeyFilePath string
}

type SanitizeResult struct {
	Accepted int64
	Rejected int64
	Bundle   string
	Manifest string
}

type SimulateRequest struct {
	Workspace string
	Policy    string
	Output    string
}

type SimulateResult struct {
	RunID  string
	Status string
	Risks  int
	Output string
}

type RenderRequest struct {
	Workspace  string
	Policy     string
	Simulation string
	Target     string
	OutputDir  string
	Acks       []string
}

type RenderResult struct {
	Target string
	Output string
	Files  int
}

type ProtectRunRequest struct {
	ConfigPath string
	Apply      bool
}

type ProtectRunResult struct {
	Mode             string
	CompleteMinutes  int64
	BaselineEligible bool
}

type ProtectSetupRequest struct {
	ConfigPath string
}

type ProtectSetupResult struct {
	HTTPInclude    string
	ServerInclude  string
	Executable     string
	ConfigPath     string
	ServiceUser    string
	ServiceGroup   string
	IncludesActive bool
}

type ProtectClearRequest struct {
	ConfigPath string
}

type ProtectApplyRequest struct {
	ConfigPath string
}
