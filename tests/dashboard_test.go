package tests

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"firmwareanalyzer/pkg/dashboard"
	"firmwareanalyzer/pkg/diff"
	"firmwareanalyzer/pkg/report"
)

func TestDashboardStoreAndServer(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	logger := log.New(io.Discard, "test", log.LstdFlags)
	store, err := dashboard.NewFileStore(dir, logger)
	if err != nil {
		t.Fatalf("store: %v", err)
	}

	ctx := context.Background()
	summary1 := report.Summary{Firmware: "fw-a.bin"}
	rec1, err := store.Record(ctx, summary1, report.Paths{}, nil, 120*time.Millisecond)
	if err != nil {
		t.Fatalf("record1: %v", err)
	}
	if _, err := os.Stat(rec1.SummaryPath); err != nil {
		t.Fatalf("summary1 not written: %v", err)
	}

	diffSource := filepath.Join(dir, "diff-source.json")
	if err := os.WriteFile(diffSource, []byte(`{"changes":true}`), 0o644); err != nil {
		t.Fatalf("write diff source: %v", err)
	}
	summary2 := report.Summary{Firmware: "fw-b.bin"}
	rec2, err := store.Record(ctx, summary2, report.Paths{}, &diff.Paths{JSON: diffSource}, 200*time.Millisecond)
	if err != nil {
		t.Fatalf("record2: %v", err)
	}
	if rec2.DiffPaths == nil || rec2.DiffPaths.JSON == "" {
		t.Fatalf("diff path not persisted: %+v", rec2.DiffPaths)
	}

	records, err := store.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}

	loaded, err := store.LoadSummary(ctx, rec1.ID)
	if err != nil {
		t.Fatalf("load summary: %v", err)
	}
	if loaded.Firmware != summary1.Firmware {
		t.Fatalf("unexpected firmware: %s", loaded.Firmware)
	}

	diffResult, err := store.Diff(ctx, rec2.ID, rec1.ID)
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	if diffResult.FirmwareNew != summary2.Firmware {
		t.Fatalf("diff firmware mismatch: %s", diffResult.FirmwareNew)
	}

	srv := dashboard.NewServer(store, logger)
	server := httptest.NewServer(srv.Handler())
	t.Cleanup(server.Close)

	// list endpoint
	resp, err := http.Get(server.URL + "/api/records")
	if err != nil {
		t.Fatalf("records request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("records status: %d", resp.StatusCode)
	}
	var apiRecords []dashboard.Record
	if err := json.NewDecoder(resp.Body).Decode(&apiRecords); err != nil {
		t.Fatalf("decode records: %v", err)
	}
	if len(apiRecords) != 2 {
		t.Fatalf("expected 2 api records, got %d", len(apiRecords))
	}

	// detail endpoint
	resp, err = http.Get(server.URL + "/api/records/" + rec1.ID)
	if err != nil {
		t.Fatalf("detail request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("detail status: %d", resp.StatusCode)
	}
	var detail struct {
		Record  dashboard.Record `json:"record"`
		Summary report.Summary   `json:"summary"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&detail); err != nil {
		t.Fatalf("decode detail: %v", err)
	}
	if detail.Summary.Firmware != summary1.Firmware {
		t.Fatalf("detail summary mismatch: %s", detail.Summary.Firmware)
	}

	// diff endpoint
	resp, err = http.Get(server.URL + "/api/diff?current=" + rec2.ID + "&baseline=" + rec1.ID)
	if err != nil {
		t.Fatalf("diff request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("diff status: %d", resp.StatusCode)
	}
	var apiDiff diff.Result
	if err := json.NewDecoder(resp.Body).Decode(&apiDiff); err != nil {
		t.Fatalf("decode diff: %v", err)
	}
	if apiDiff.FirmwareNew != summary2.Firmware {
		t.Fatalf("api diff mismatch: %s", apiDiff.FirmwareNew)
	}
}
