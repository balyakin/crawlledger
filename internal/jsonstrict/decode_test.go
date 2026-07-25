package jsonstrict

import (
	"strings"
	"testing"
)

func TestDecodeRejectsDeepNesting(t *testing.T) {
	data := []byte(strings.Repeat("[", maxDepth+1) + "0" + strings.Repeat("]", maxDepth+1))
	var value any
	if err := Decode(data, &value); err == nil {
		t.Fatal("deeply nested JSON was accepted")
	}
}
