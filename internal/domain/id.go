package domain

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"strings"
)

var randomReader io.Reader = rand.Reader

func NewAnalysisID() (string, error) {
	var bytes [16]byte
	if _, err := io.ReadFull(randomReader, bytes[:]); err != nil {
		return "", err
	}
	return "an_" + hex.EncodeToString(bytes[:]), nil
}

func FindingID(kind FindingKind, route, subject string) string {
	sum := stableHash("finding-v1", string(kind), route, subject)
	return "fd_" + hex.EncodeToString(sum[:8])
}

func SimulationRunID(analysisID, policyHash string) (string, error) {
	if len(analysisID) != 35 || !strings.HasPrefix(analysisID, "an_") || !lowerHex(analysisID[3:], 32) ||
		!lowerHex(policyHash, 64) {
		return "", errors.New("invalid analysis ID or policy hash")
	}
	sum := stableHash("simulation-v1", analysisID, policyHash)
	return "pr_" + hex.EncodeToString(sum[:8]), nil
}

func stableHash(purpose string, fields ...string) [32]byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte(purpose))
	_, _ = hash.Write([]byte{0})
	var length [4]byte
	for _, field := range fields {
		binary.BigEndian.PutUint32(length[:], uint32(len(field)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write([]byte(field))
	}
	var sum [32]byte
	copy(sum[:], hash.Sum(nil))
	return sum
}
