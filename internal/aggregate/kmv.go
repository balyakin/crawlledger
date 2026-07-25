package aggregate

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/big"
	"sort"
)

const kmvK = 64

type Sketch struct{ values []uint64 }

// ponytail: k=64 bounds each sketch and gives a conservative signal for v1;
// raise k only after measured false-negative evidence and a workspace migration.

func (s *Sketch) Add(value string) {
	hash := sha256.Sum256([]byte(value))
	s.AddHash(binary.BigEndian.Uint64(hash[:8]))
}

func (s *Sketch) AddHash(value uint64) {
	index := sort.Search(len(s.values), func(index int) bool { return s.values[index] >= value })
	if index < len(s.values) && s.values[index] == value {
		return
	}
	if len(s.values) == kmvK && index == len(s.values) {
		return
	}
	s.values = append(s.values, 0)
	copy(s.values[index+1:], s.values[index:])
	s.values[index] = value
	if len(s.values) > kmvK {
		s.values = s.values[:kmvK]
	}
}

func (s *Sketch) Merge(other Sketch) {
	for _, value := range other.values {
		s.AddHash(value)
	}
}

func (s Sketch) Estimate(totalRequests int64) int64 {
	if len(s.values) < kmvK {
		return int64(len(s.values))
	}
	kth := s.values[kmvK-1]
	if kth == 0 {
		return min(totalRequests, kmvK)
	}
	numerator := new(big.Int).Lsh(big.NewInt(kmvK-1), 64)
	estimate := numerator.Quo(numerator, new(big.Int).SetUint64(kth))
	if !estimate.IsInt64() || estimate.Int64() > totalRequests {
		return totalRequests
	}
	if estimate.Int64() < kmvK {
		return kmvK
	}
	return estimate.Int64()
}

func (s Sketch) Conservative(totalRequests int64) int64 {
	estimate := s.Estimate(totalRequests)
	if len(s.values) < kmvK {
		return estimate
	}
	return estimate/1_000_000*619_000 + estimate%1_000_000*619_000/1_000_000
}

func (s Sketch) Approximate() bool { return len(s.values) == kmvK }

func (s Sketch) MarshalBinary() ([]byte, error) {
	result := make([]byte, 3+8*len(s.values))
	result[0] = 1
	binary.BigEndian.PutUint16(result[1:3], uint16(len(s.values)))
	for index, value := range s.values {
		binary.BigEndian.PutUint64(result[3+index*8:], value)
	}
	return result, nil
}

func (s *Sketch) UnmarshalBinary(data []byte) error {
	if len(data) < 3 || data[0] != 1 {
		return errors.New("invalid KMV encoding")
	}
	count := int(binary.BigEndian.Uint16(data[1:3]))
	if count > kmvK || len(data) != 3+count*8 {
		return errors.New("invalid KMV length")
	}
	values := make([]uint64, count)
	for index := range values {
		values[index] = binary.BigEndian.Uint64(data[3+index*8:])
		if index > 0 && values[index-1] >= values[index] {
			return errors.New("KMV values are not sorted unique")
		}
	}
	s.values = values
	return nil
}
