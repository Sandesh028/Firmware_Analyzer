package tests

import (
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
