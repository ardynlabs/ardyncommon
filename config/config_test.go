package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRejectsUnknownFields(t *testing.T) {
	t.Parallel()
	type configuration struct {
		Name string `yaml:"name"`
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("name: api\ntypo: value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var destination configuration
	if err := Load(path, &destination); err == nil {
		t.Fatal("Load() error = nil, want unknown-field error")
	}
}

func TestLoadRejectsInvalidDestinationAndMultipleDocuments(t *testing.T) {
	t.Parallel()
	if err := Load("unused", nil); !errors.Is(err, ErrDestination) {
		t.Fatalf("Load() error = %v, want ErrDestination", err)
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("name: api\n---\nname: worker\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var destination struct {
		Name string `yaml:"name"`
	}
	if err := Load(path, &destination); err == nil {
		t.Fatal("Load() error = nil, want multi-document error")
	}
}
