package parser

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

const maxJSONDepth = 128

func rejectDuplicateJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := walkValue(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON")
	}
	return nil
}

func walkValue(decoder *json.Decoder, depth int) error {
	if depth > maxJSONDepth {
		return errors.New("JSON nesting is too deep")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	if delimiter == '{' {
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("invalid object key")
			}
			if _, exists := seen[key]; exists {
				return errors.New("duplicate object key")
			}
			seen[key] = struct{}{}
			if err := walkValue(decoder, depth+1); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	}
	if delimiter == '[' {
		for decoder.More() {
			if err := walkValue(decoder, depth+1); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	}
	return errors.New("unexpected JSON delimiter")
}

func decodeOne(data []byte, value any, strict bool) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if strict {
		decoder.DisallowUnknownFields()
	}
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON")
	}
	return nil
}
