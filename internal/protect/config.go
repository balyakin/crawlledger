package protect

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/balyakin/crawlledger/internal/domain"
	"github.com/balyakin/crawlledger/internal/jsonstrict"
)

const maxConfigBytes int64 = 1 << 20

var sitePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

type Config struct {
	SchemaVersion     int           `json:"schema_version"`
	Site              string        `json:"site"`
	LogPath           string        `json:"log_path"`
	BaselineWorkspace string        `json:"baseline_workspace"`
	Nginx             NginxConfig   `json:"nginx"`
	Runtime           RuntimeConfig `json:"runtime"`
	Detection         Detection     `json:"detection"`
	Action            Action        `json:"action"`
	Exclusions        Exclusions    `json:"exclusions"`
	StaticDeny        StaticDeny    `json:"static_deny"`
}

type NginxConfig struct {
	Binary     string `json:"binary"`
	ConfigPath string `json:"config_path"`
	ManagedDir string `json:"managed_dir"`
}

type RuntimeConfig struct {
	StateFile       string `json:"state_file"`
	MaxLogLineBytes int    `json:"max_log_line_bytes"`
}

type Detection struct {
	WindowSeconds                     int   `json:"window_seconds"`
	EvaluationIntervalSeconds         int   `json:"evaluation_interval_seconds"`
	RequiredConsecutiveEvaluations    int   `json:"required_consecutive_evaluations"`
	MaxEventLagSeconds                int   `json:"max_event_lag_seconds"`
	BaselineMultiplier                int64 `json:"baseline_multiplier"`
	VolumeMinRequests                 int64 `json:"volume_min_requests"`
	VolumeMinSiteSharePPM             int64 `json:"volume_min_site_share_ppm"`
	DistributedMinRequests            int64 `json:"distributed_min_requests"`
	DistributedMinClients             int64 `json:"distributed_min_clients"`
	DistributedMinClientRatioPPM      int64 `json:"distributed_min_client_ratio_ppm"`
	DistributedMinUpstreamCoveragePPM int64 `json:"distributed_min_upstream_coverage_ppm"`
	DistributedMinUpstreamUS          int64 `json:"distributed_min_upstream_us"`
	DistributedMinAverageUpstreamUS   int64 `json:"distributed_min_average_upstream_us"`
	MaxTrackedGroups                  int   `json:"max_tracked_groups"`
}

type Action struct {
	TTLSeconds               int `json:"ttl_seconds"`
	RateRequestsPerSecond    int `json:"rate_requests_per_second"`
	Burst                    int `json:"burst"`
	MaxActiveRules           int `json:"max_active_rules"`
	MinReloadIntervalSeconds int `json:"min_reload_interval_seconds"`
}

type Exclusions struct {
	Methods      []string `json:"methods"`
	PathPrefixes []string `json:"path_prefixes"`
}

type StaticDeny struct {
	Enabled []string `json:"enabled"`
}

type LoadedConfig struct {
	Config Config
	Path   string
	Bytes  []byte
	SHA256 string
}

func LoadConfig(path string) (LoadedConfig, error) {
	data, absolute, err := readConfig(path)
	if err != nil {
		return LoadedConfig{}, err
	}
	var config Config
	if err := jsonstrict.Decode(data, &config); err != nil {
		return LoadedConfig{}, fmt.Errorf("decode protection config: %w", err)
	}
	if err := config.Validate(); err != nil {
		return LoadedConfig{}, fmt.Errorf("validate protection config: %w", err)
	}
	sum := sha256.Sum256(data)
	return LoadedConfig{
		Config: config,
		Path:   absolute,
		Bytes:  append([]byte(nil), data...),
		SHA256: hex.EncodeToString(sum[:]),
	}, nil
}

func readConfig(path string) ([]byte, string, error) {
	if path == "" {
		return nil, "", errors.New("protection config path is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, "", err
	}
	parent, name := filepath.Split(filepath.Clean(absolute))
	if name == "" || name == "." || name == ".." {
		return nil, "", errors.New("invalid protection config name")
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		return nil, "", err
	}
	defer root.Close()
	info, err := root.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > maxConfigBytes {
		return nil, "", errors.Join(err, errors.New("protection config must be a bounded regular non-symlink file"))
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, "", err
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		_ = file.Close()
		return nil, "", errors.Join(err, errors.New("protection config changed while opening"))
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maxConfigBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || int64(len(data)) > maxConfigBytes {
		return nil, "", errors.Join(readErr, closeErr, errors.New("cannot read bounded protection config"))
	}
	return data, absolute, nil
}

func (config Config) Validate() error {
	if config.SchemaVersion != 1 {
		return errors.New("schema_version must be 1")
	}
	if !sitePattern.MatchString(config.Site) {
		return errors.New("site is invalid")
	}
	for name, path := range map[string]string{
		"log_path":           config.LogPath,
		"baseline_workspace": config.BaselineWorkspace,
		"nginx.binary":       config.Nginx.Binary,
		"nginx.config_path":  config.Nginx.ConfigPath,
		"nginx.managed_dir":  config.Nginx.ManagedDir,
		"runtime.state_file": config.Runtime.StateFile,
	} {
		if !absoluteCleanPath(path) {
			return fmt.Errorf("%s must be an absolute clean path", name)
		}
	}
	if err := config.validateDetection(); err != nil {
		return err
	}
	if err := config.validateAction(); err != nil {
		return err
	}
	if config.Exclusions.Methods == nil || config.Exclusions.PathPrefixes == nil || config.StaticDeny.Enabled == nil {
		return errors.New("exclusion and static deny lists are required")
	}
	if err := validateUnique(config.Exclusions.Methods, domain.ValidMethod, "excluded method"); err != nil {
		return err
	}
	if err := validateUnique(config.Exclusions.PathPrefixes, domain.ValidActionable, "excluded path prefix"); err != nil {
		return err
	}
	return validateUnique(config.StaticDeny.Enabled, domain.ValidProbeID, "static deny ID")
}

func (config Config) validateDetection() error {
	detection := config.Detection
	checks := []struct {
		name    string
		value   int64
		minimum int64
		maximum int64
	}{
		{"runtime.max_log_line_bytes", int64(config.Runtime.MaxLogLineBytes), 4096, 16 << 20},
		{"detection.window_seconds", int64(detection.WindowSeconds), 10, 300},
		{"detection.evaluation_interval_seconds", int64(detection.EvaluationIntervalSeconds), 1, 60},
		{"detection.required_consecutive_evaluations", int64(detection.RequiredConsecutiveEvaluations), 1, 6},
		{"detection.max_event_lag_seconds", int64(detection.MaxEventLagSeconds), 30, 3600},
		{"detection.baseline_multiplier", detection.BaselineMultiplier, 2, 100},
		{"detection.volume_min_requests", detection.VolumeMinRequests, 1, 10000000},
		{"detection.volume_min_site_share_ppm", detection.VolumeMinSiteSharePPM, 1, 1000000},
		{"detection.distributed_min_requests", detection.DistributedMinRequests, 1, 10000000},
		{"detection.distributed_min_clients", detection.DistributedMinClients, 1, 10000000},
		{"detection.distributed_min_client_ratio_ppm", detection.DistributedMinClientRatioPPM, 1, 1000000},
		{"detection.distributed_min_upstream_coverage_ppm", detection.DistributedMinUpstreamCoveragePPM, 1, 1000000},
		{"detection.distributed_min_upstream_us", detection.DistributedMinUpstreamUS, 1, 86400000000},
		{"detection.distributed_min_average_upstream_us", detection.DistributedMinAverageUpstreamUS, 1, 60000000},
		{"detection.max_tracked_groups", int64(detection.MaxTrackedGroups), 100, 100000},
	}
	for _, check := range checks {
		if check.value < check.minimum || check.value > check.maximum {
			return fmt.Errorf("%s must be between %d and %d", check.name, check.minimum, check.maximum)
		}
	}
	if detection.WindowSeconds%detection.EvaluationIntervalSeconds != 0 {
		return errors.New("evaluation_interval_seconds must divide window_seconds")
	}
	if detection.DistributedMinClients > detection.DistributedMinRequests {
		return errors.New("distributed_min_clients cannot exceed distributed_min_requests")
	}
	buckets := detection.WindowSeconds/detection.EvaluationIntervalSeconds + 1
	if int64(detection.MaxTrackedGroups) > 100000/int64(buckets) {
		return errors.New("tracked bucket capacity exceeds 100000")
	}
	return nil
}

func (config Config) validateAction() error {
	action := config.Action
	checks := []struct {
		name    string
		value   int
		minimum int
		maximum int
	}{
		{"action.ttl_seconds", action.TTLSeconds, 60, 86400},
		{"action.rate_requests_per_second", action.RateRequestsPerSecond, 1, 10000},
		{"action.burst", action.Burst, 0, 100000},
		{"action.max_active_rules", action.MaxActiveRules, 1, 128},
		{"action.min_reload_interval_seconds", action.MinReloadIntervalSeconds, 1, 60},
	}
	for _, check := range checks {
		if check.value < check.minimum || check.value > check.maximum {
			return fmt.Errorf("%s must be between %d and %d", check.name, check.minimum, check.maximum)
		}
	}
	if action.TTLSeconds < config.Detection.WindowSeconds {
		return errors.New("ttl_seconds cannot be shorter than window_seconds")
	}
	if action.MinReloadIntervalSeconds > action.TTLSeconds {
		return errors.New("min_reload_interval_seconds cannot exceed ttl_seconds")
	}
	return nil
}

func absoluteCleanPath(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.ContainsRune(path, 0)
}

func validateUnique(values []string, valid func(string) bool, name string) error {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !valid(value) {
			return fmt.Errorf("invalid %s %q", name, value)
		}
		if _, exists := seen[value]; exists {
			return fmt.Errorf("duplicate %s %q", name, value)
		}
		seen[value] = struct{}{}
	}
	return nil
}
