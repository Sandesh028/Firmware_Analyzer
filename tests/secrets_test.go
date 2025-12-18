package tests

import (
	"context"
	"os"
	"path/filepath"
	"strings"
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

	var hasPassword bool
	for _, finding := range findings {
		if finding.Rule == "Password Assignment" {
			hasPassword = true
		}
	}
	if !hasPassword {
		t.Fatalf("expected password assignment rule, got %#v", findings)
	}
}

func TestSecretsScannerDetectsJWTAndAllowsSuppression(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	file := filepath.Join(root, "tokens.txt")
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkRyb25lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	slack := "xoxb-1234567890-token"
	content := "JWT=" + jwt + "\nSLACK=" + slack + "\n"
	if err := os.WriteFile(file, []byte(content), 0o644); err != nil {
		t.Fatalf("write token file: %v", err)
	}

	scanner := secrets.NewScanner(nil, nil)
	findings, err := scanner.Scan(context.Background(), root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	var hasJWT, hasSlack bool
	for _, finding := range findings {
		if finding.Rule == "JWT" {
			hasJWT = true
		}
		if finding.Rule == "Slack Token" {
			hasSlack = true
		}
	}
	if !hasJWT || !hasSlack {
		t.Fatalf("expected jwt and slack detections, got %#v", findings)
	}

	opts := secrets.ScannerOptions{
		AllowRulePatterns: map[string][]string{
			"Slack Token": {"xoxb-*"},
		},
	}
	scanner = secrets.NewScannerWithOptions(nil, opts)
	findings, err = scanner.Scan(context.Background(), root)
	if err != nil {
		t.Fatalf("scan with suppression: %v", err)
	}
	for _, finding := range findings {
		if finding.Rule == "Slack Token" {
			t.Fatalf("expected slack token to be suppressed, got %#v", findings)
		}
	}
}

func TestSecretsScannerHandlesLongLines(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	file := filepath.Join(root, "long.txt")
	longValue := strings.Repeat("A", 200000)
	if err := os.WriteFile(file, []byte("token="+longValue), 0o644); err != nil {
		t.Fatalf("write long file: %v", err)
	}

	scanner := secrets.NewScanner(nil, nil)
	if _, err := scanner.Scan(context.Background(), root); err != nil {
		t.Fatalf("scan long file: %v", err)
	}
}
