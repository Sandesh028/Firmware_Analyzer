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

func TestConfigParserSkipsMalformedXML(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	jsonPath := filepath.Join(root, "valid.json")
	if err := os.WriteFile(jsonPath, []byte(`{"service":"ok"}`), 0o644); err != nil {
		t.Fatalf("write json: %v", err)
	}
	badXML := filepath.Join(root, "broken.xml")
	if err := os.WriteFile(badXML, []byte(`<config><value>bad&value</value></config>`), 0o644); err != nil {
		t.Fatalf("write bad xml: %v", err)
	}

	parser := configparser.NewParser(nil)
	findings, err := parser.Parse(context.Background(), root)
	if err != nil {
		t.Fatalf("parse configs: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected only the valid json to produce findings, got %d", len(findings))
	}
	if findings[0].File != jsonPath {
		t.Fatalf("unexpected finding file %s", findings[0].File)
	}
}
