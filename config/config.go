// Package config loads service configuration files.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"

	"gopkg.in/yaml.v3"
)

var ErrDestination = errors.New("configuration destination must be a non-nil pointer")

// Load decodes exactly one YAML document into destination. Unknown fields are
// rejected so configuration typos do not silently reach production.
func Load(path string, destination any) error {
	if path == "" {
		return errors.New("configuration path is required")
	}
	if destination == nil || reflect.ValueOf(destination).Kind() != reflect.Ptr || reflect.ValueOf(destination).IsNil() {
		return ErrDestination
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read configuration %q: %w", path, err)
	}
	return decode(data, destination)
}

func decode(data []byte, destination any) error {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode configuration: %w", err)
	}

	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("decode configuration: multiple YAML documents are not supported")
		}
		return fmt.Errorf("decode configuration: %w", err)
	}
	return nil
}
