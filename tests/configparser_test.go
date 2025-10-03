package tests

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"firmwareanalyzer/pkg/configparser"
)

func TestConfigParserParsesMultipleFormats(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	jsonPath := filepath.Join(root, "settings.json")
	if err := os.WriteFile(jsonPath, []byte(`{"db":{"user":"root","password":"toor"}}`), 0o644); err != nil {
		t.Fatalf("write json: %v", err)
	}
	xmlPath := filepath.Join(root, "config.xml")
	if err := os.WriteFile(xmlPath, []byte(`<config><api token="abc123">value</api></config>`), 0o644); err != nil {
		t.Fatalf("write xml: %v", err)
	}
	tomlPath := filepath.Join(root, "app.toml")
	if err := os.WriteFile(tomlPath, []byte("[auth]\nkey = \"abcdef\"\n"), 0o644); err != nil {
		t.Fatalf("write toml: %v", err)
	}
	iniPath := filepath.Join(root, "network.ini")
	if err := os.WriteFile(iniPath, []byte("[wifi]\npassword=secret\n"), 0o644); err != nil {
		t.Fatalf("write ini: %v", err)
	}
	yamlPath := filepath.Join(root, "drone.yaml")
	yamlContent := "credentials:\n  token: abcdef123456\n  endpoints:\n    - https://example\n"
	if err := os.WriteFile(yamlPath, []byte(yamlContent), 0o644); err != nil {
		t.Fatalf("write yaml: %v", err)
	}

	parser := configparser.NewParser(nil)
	findings, err := parser.Parse(context.Background(), root)
	if err != nil {
		t.Fatalf("parse configs: %v", err)
	}

	if len(findings) != 5 {
		t.Fatalf("expected 5 findings, got %d", len(findings))
	}

	var credentialCount int
	for _, finding := range findings {
		for _, param := range finding.Params {
			if param.Credential {
				credentialCount++
			}
		}
	}
	if credentialCount == 0 {
		t.Fatalf("expected credential heuristics to trigger")
	}
}
