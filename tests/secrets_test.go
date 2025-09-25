package tests

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"firmwareanalyzer/pkg/secrets"
)

func TestSecretsScannerFindsPasswords(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	file := filepath.Join(root, "credentials.txt")
	if err := os.WriteFile(file, []byte("username=admin\npassword=SuperSecret123\n"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	scanner := secrets.NewScanner(nil, nil)
	findings, err := scanner.Scan(context.Background(), root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if len(findings) == 0 {
		t.Fatalf("expected secret finding, got %#v", findings)
	}
}
