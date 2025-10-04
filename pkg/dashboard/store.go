package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"firmwareanalyzer/pkg/diff"
	"firmwareanalyzer/pkg/report"
)

// Record captures metadata about a completed firmware analysis run.
type Record struct {
	ID          string       `json:"id"`
	Firmware    string       `json:"firmware"`
	Timestamp   time.Time    `json:"timestamp"`
	Duration    string       `json:"duration"`
	ReportDir   string       `json:"report_dir,omitempty"`
	ReportPaths report.Paths `json:"report_paths"`
	SummaryPath string       `json:"summary_path"`
	DiffPaths   *diff.Paths  `json:"diff_paths,omitempty"`
}

// Store exposes read operations for persisted analysis history.
type Store interface {
	List(ctx context.Context) ([]Record, error)
	Get(ctx context.Context, id string) (Record, error)
	LoadSummary(ctx context.Context, id string) (report.Summary, error)
	Diff(ctx context.Context, currentID, baselineID string) (diff.Result, error)
}

// Recorder persists analysis results for future browsing.
type Recorder interface {
	Record(ctx context.Context, summary report.Summary, paths report.Paths, diffPaths *diff.Paths, duration time.Duration) (Record, error)
}

// FileStore stores history entries on disk using one directory per run.
type FileStore struct {
	root   string
	logger *log.Logger
	mu     sync.Mutex
}

// NewFileStore initialises a FileStore backed by the supplied directory.
func NewFileStore(root string, logger *log.Logger) (*FileStore, error) {
	if strings.TrimSpace(root) == "" {
		return nil, fmt.Errorf("history directory must be provided")
	}
	if logger == nil {
		logger = log.New(io.Discard, "dashboard", log.LstdFlags)
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, err
	}
	return &FileStore{root: root, logger: logger}, nil
}

// Record persists the supplied analysis summary and associated artefacts.
func (s *FileStore) Record(ctx context.Context, summary report.Summary, paths report.Paths, diffPaths *diff.Paths, duration time.Duration) (Record, error) {
	if ctx.Err() != nil {
		return Record{}, ctx.Err()
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	id := fmt.Sprintf("%d", time.Now().UnixNano())
	recordDir := filepath.Join(s.root, id)
	if err := os.MkdirAll(recordDir, 0o755); err != nil {
		return Record{}, err
	}
	timestamp := time.Now().UTC()

	summaryPath := filepath.Join(recordDir, "summary.json")
	if err := s.writeSummary(summary, paths.JSON, summaryPath); err != nil {
		return Record{}, err
	}

	storedDiff, err := s.persistDiff(recordDir, diffPaths)
	if err != nil {
		return Record{}, err
	}

	record := Record{
		ID:          id,
		Firmware:    summary.Firmware,
		Timestamp:   timestamp,
		Duration:    duration.Round(time.Millisecond).String(),
		ReportDir:   deriveReportDir(paths),
		ReportPaths: paths,
		SummaryPath: summaryPath,
		DiffPaths:   storedDiff,
	}

	recordData, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return Record{}, err
	}
	if err := os.WriteFile(filepath.Join(recordDir, "record.json"), recordData, 0o644); err != nil {
		return Record{}, err
	}
	s.logger.Printf("history stored %s", id)
	return record, nil
}

// List returns all recorded runs ordered by most recent first.
func (s *FileStore) List(ctx context.Context) ([]Record, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	entries, err := os.ReadDir(s.root)
	if err != nil {
		return nil, err
	}
	var records []Record
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		rec, err := s.readRecord(filepath.Join(s.root, entry.Name()))
		if err != nil {
			s.logger.Printf("skip corrupt record %s: %v", entry.Name(), err)
			continue
		}
		records = append(records, rec)
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].Timestamp.After(records[j].Timestamp)
	})
	return records, nil
}

// Get retrieves a single record by identifier.
func (s *FileStore) Get(ctx context.Context, id string) (Record, error) {
	if ctx.Err() != nil {
		return Record{}, ctx.Err()
	}
	return s.readRecord(filepath.Join(s.root, id))
}

// LoadSummary loads the stored summary for the given record.
func (s *FileStore) LoadSummary(ctx context.Context, id string) (report.Summary, error) {
	if ctx.Err() != nil {
		return report.Summary{}, ctx.Err()
	}
	record, err := s.Get(ctx, id)
	if err != nil {
		return report.Summary{}, err
	}
	return report.LoadJSON(record.SummaryPath)
}

// Diff computes the differences between two records.
func (s *FileStore) Diff(ctx context.Context, currentID, baselineID string) (diff.Result, error) {
	if ctx.Err() != nil {
		return diff.Result{}, ctx.Err()
	}
	current, err := s.LoadSummary(ctx, currentID)
	if err != nil {
		return diff.Result{}, err
	}
	baseline, err := s.LoadSummary(ctx, baselineID)
	if err != nil {
		return diff.Result{}, err
	}
	return diff.Compute(current, baseline), nil
}

func (s *FileStore) readRecord(dir string) (Record, error) {
	data, err := os.ReadFile(filepath.Join(dir, "record.json"))
	if err != nil {
		return Record{}, err
	}
	var record Record
	if err := json.Unmarshal(data, &record); err != nil {
		return Record{}, err
	}
	if !filepath.IsAbs(record.SummaryPath) {
		record.SummaryPath = filepath.Join(dir, record.SummaryPath)
	}
	if record.DiffPaths != nil {
		if record.DiffPaths.Markdown != "" && !filepath.IsAbs(record.DiffPaths.Markdown) {
			record.DiffPaths.Markdown = filepath.Join(dir, record.DiffPaths.Markdown)
		}
		if record.DiffPaths.JSON != "" && !filepath.IsAbs(record.DiffPaths.JSON) {
			record.DiffPaths.JSON = filepath.Join(dir, record.DiffPaths.JSON)
		}
	}
	return record, nil
}

func (s *FileStore) writeSummary(summary report.Summary, existing, dest string) error {
	if existing != "" {
		data, err := os.ReadFile(existing)
		if err == nil {
			return os.WriteFile(dest, data, 0o644)
		}
		s.logger.Printf("unable to copy existing summary %s: %v", existing, err)
	}
	data, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(dest, data, 0o644)
}

func (s *FileStore) persistDiff(dir string, diffPaths *diff.Paths) (*diff.Paths, error) {
	if diffPaths == nil {
		return nil, nil
	}
	var stored diff.Paths
	if diffPaths.Markdown != "" {
		if err := copyFile(diffPaths.Markdown, filepath.Join(dir, "diff.md")); err != nil {
			return nil, err
		}
		stored.Markdown = filepath.Join(dir, "diff.md")
	}
	if diffPaths.JSON != "" {
		if err := copyFile(diffPaths.JSON, filepath.Join(dir, "diff.json")); err != nil {
			return nil, err
		}
		stored.JSON = filepath.Join(dir, "diff.json")
	}
	if stored.Markdown == "" && stored.JSON == "" {
		return nil, nil
	}
	return &stored, nil
}

func copyFile(src, dest string) error {
	if src == "" {
		return nil
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dest, data, 0o644)
}

func deriveReportDir(paths report.Paths) string {
	for _, candidate := range []string{paths.Markdown, paths.HTML, paths.JSON} {
		if candidate != "" {
			return filepath.Dir(candidate)
		}
	}
	return ""
}
