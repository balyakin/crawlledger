package protect

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/balyakin/crawlledger/internal/domain"
	"github.com/balyakin/crawlledger/internal/jsonstrict"
)

const maxStateBytes = 256 << 10
const maxApplyBytes = 64 << 10
const maxProtectionRules = 128

type State struct {
	SchemaVersion          int     `json:"schema_version"`
	Site                   string  `json:"site"`
	ConfigSHA256           string  `json:"config_sha256"`
	BaselineManifestSHA256 *string `json:"baseline_manifest_sha256"`
	Rules                  []Rule  `json:"rules"`
}

type Rule struct {
	Method             string   `json:"method"`
	PathPrefix         string   `json:"path_prefix"`
	Reasons            []string `json:"reasons"`
	RequestThreshold   int64    `json:"request_threshold"`
	FirstQualifiedAtUS int64    `json:"first_qualified_at_us"`
	LastQualifiedAtUS  int64    `json:"last_qualified_at_us"`
	ExpiresAtUS        int64    `json:"expires_at_us"`
}

type ApplyPayload struct {
	SchemaVersion int         `json:"schema_version"`
	Site          string      `json:"site"`
	Rules         []ApplyRule `json:"rules"`
}

type ApplyRule struct {
	Method     string `json:"method"`
	PathPrefix string `json:"path_prefix"`
}

func DecodeState(data []byte) (State, error) {
	if len(data) > maxStateBytes {
		return State{}, errors.New("state exceeds 256 KiB")
	}
	var state State
	if err := jsonstrict.Decode(data, &state); err != nil {
		return State{}, fmt.Errorf("decode state: %w", err)
	}
	if err := state.Validate(); err != nil {
		return State{}, err
	}
	return state, nil
}

func EncodeState(state State) ([]byte, error) {
	if err := state.Validate(); err != nil {
		return nil, err
	}
	return marshalLine(state, maxStateBytes)
}

func (state State) Validate() error {
	if state.SchemaVersion != 1 || !sitePattern.MatchString(state.Site) || !lowerDigest(state.ConfigSHA256) {
		return errors.New("invalid state identity")
	}
	if state.Rules == nil || len(state.Rules) > maxProtectionRules {
		return errors.New("state rules are required and cannot exceed 128")
	}
	if state.BaselineManifestSHA256 == nil {
		if len(state.Rules) != 0 {
			return errors.New("non-empty state requires a baseline digest")
		}
	} else if !lowerDigest(*state.BaselineManifestSHA256) {
		return errors.New("invalid baseline digest")
	}
	for index, rule := range state.Rules {
		if err := rule.Validate(); err != nil {
			return fmt.Errorf("rule %d: %w", index, err)
		}
		if index > 0 && !ruleLess(state.Rules[index-1], rule) {
			return errors.New("state rules must be sorted and unique")
		}
	}
	return nil
}

func (rule Rule) Validate() error {
	if !domain.ValidMethod(rule.Method) || !domain.ValidActionable(rule.PathPrefix) {
		return errors.New("invalid method or path prefix")
	}
	if len(rule.Reasons) < 1 || len(rule.Reasons) > 2 {
		return errors.New("rule must have one or two reasons")
	}
	for index, reason := range rule.Reasons {
		if reason != "distributed-expense" && reason != "extreme-volume" {
			return errors.New("invalid rule reason")
		}
		if index > 0 && rule.Reasons[index-1] >= reason {
			return errors.New("rule reasons must be sorted and unique")
		}
	}
	if rule.RequestThreshold <= 0 || rule.FirstQualifiedAtUS <= 0 ||
		rule.FirstQualifiedAtUS > rule.LastQualifiedAtUS || rule.LastQualifiedAtUS >= rule.ExpiresAtUS {
		return errors.New("invalid rule threshold or timestamps")
	}
	return nil
}

func ProjectState(state State) ([]byte, error) {
	if err := state.Validate(); err != nil {
		return nil, err
	}
	payload := ApplyPayload{SchemaVersion: 1, Site: state.Site, Rules: make([]ApplyRule, len(state.Rules))}
	for index, rule := range state.Rules {
		payload.Rules[index] = ApplyRule{Method: rule.Method, PathPrefix: rule.PathPrefix}
	}
	return encodeApplyPayload(payload)
}

func DecodeApplyPayload(data []byte) ([]byte, error) {
	if len(data) > maxApplyBytes {
		return nil, errors.New("apply payload exceeds 64 KiB")
	}
	var payload ApplyPayload
	if err := jsonstrict.Decode(data, &payload); err != nil {
		return nil, fmt.Errorf("decode apply payload: %w", err)
	}
	return encodeApplyPayload(payload)
}

func encodeApplyPayload(payload ApplyPayload) ([]byte, error) {
	if err := payload.Validate(); err != nil {
		return nil, err
	}
	return marshalLine(payload, maxApplyBytes)
}

func (payload ApplyPayload) Validate() error {
	if payload.SchemaVersion != 1 || !sitePattern.MatchString(payload.Site) || payload.Rules == nil ||
		len(payload.Rules) > maxProtectionRules {
		return errors.New("invalid apply payload identity")
	}
	for index, rule := range payload.Rules {
		if !domain.ValidMethod(rule.Method) || !domain.ValidActionable(rule.PathPrefix) {
			return errors.New("invalid apply rule")
		}
		if index > 0 {
			previous := payload.Rules[index-1]
			if previous.Method > rule.Method || previous.Method == rule.Method && previous.PathPrefix >= rule.PathPrefix {
				return errors.New("apply rules must be sorted and unique")
			}
		}
	}
	return nil
}

func marshalLine(value any, limit int) ([]byte, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	data = append(data, '\n')
	if len(data) > limit {
		return nil, errors.New("canonical JSON exceeds limit")
	}
	return data, nil
}

func lowerDigest(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func ruleLess(left, right Rule) bool {
	return left.Method < right.Method || left.Method == right.Method && left.PathPrefix < right.PathPrefix
}
