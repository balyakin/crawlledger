package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/balyakin/crawlledger/internal/domain"
)

func Canonical(value domain.Policy) ([]byte, string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(data)
	return data, hex.EncodeToString(sum[:]), nil
}

func CanonicalSimulation(value domain.Simulation) ([]byte, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}
