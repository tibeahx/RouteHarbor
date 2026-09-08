package helper

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// DecodeStrict rejects unknown fields, duplicate object keys, trailing data,
// oversized messages and deeply nested input before decoding a typed operation.
func DecodeStrict(data []byte, dst any) error {
	if len(data) > MaxRequestBytes {
		return errors.New("request_too_large")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := walkJSON(d, 0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("invalid_json: trailing data")
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		return errors.New("invalid_request: payload does not match the operation schema")
	}
	return nil
}

func walkJSON(d *json.Decoder, depth int) error {
	if depth > 24 {
		return errors.New("invalid_json: nesting limit exceeded")
	}
	tok, err := d.Token()
	if err != nil {
		return errors.New("invalid_json")
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		keys := map[string]bool{}
		for d.More() {
			t, e := d.Token()
			if e != nil {
				return errors.New("invalid_json")
			}
			key, ok := t.(string)
			if !ok || keys[key] {
				return errors.New("invalid_json: duplicate key")
			}
			keys[key] = true
			if err = walkJSON(d, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for d.More() {
			if err = walkJSON(d, depth+1); err != nil {
				return err
			}
		}
	default:
		return errors.New("invalid_json")
	}
	_, err = d.Token()
	return err
}
