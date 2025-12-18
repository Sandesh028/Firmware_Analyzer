package tests

import (
	"os"
	"path/filepath"
	"testing"

	"firmwareanalyzer/pkg/utils"
)

func TestFlattenProducesDotNotation(t *testing.T) {
	input := map[string]any{
		"db": map[string]any{
			"host": "localhost",
			"creds": map[string]any{
				"user": "root",
				"pass": "secret",
			},
		},
	}
	flat := utils.Flatten("", input)
	if flat["db.host"] != "localhost" {
		t.Fatalf("unexpected host: %v", flat["db.host"])
	}
	if _, ok := flat["db.creds.pass"]; !ok {
		t.Fatalf("expected credential path in flattened map")
	}
}

func TestShannonEntropyRanges(t *testing.T) {
	if utils.ShannonEntropy("aaaaa") >= utils.ShannonEntropy("abc123XYZ") {
		t.Fatalf("expected higher entropy for mixed string")
	}
}

func TestLooksLikeRoot(t *testing.T) {
	dir := t.TempDir()
	must := func(err error) {
		if err != nil {
			t.Fatalf("setup: %v", err)
		}
	}
	must(os.Mkdir(filepath.Join(dir, "etc"), 0o755))
	must(os.Mkdir(filepath.Join(dir, "bin"), 0o755))
	must(os.WriteFile(filepath.Join(dir, "etc", "fstab"), []byte(""), 0o644))

	if !utils.LooksLikeRoot(dir) {
		t.Fatalf("expected directory to look like root")
	}

	other := t.TempDir()
	if utils.LooksLikeRoot(other) {
		t.Fatalf("unexpected root detection for empty dir")
	}
}
