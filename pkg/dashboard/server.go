package dashboard

import (
	"context"
	"encoding/json"
	"html/template"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"firmwareanalyzer/pkg/report"
)

// Server exposes a minimal web UI and JSON API for browsing analysis history.
type Server struct {
	store  Store
	logger *log.Logger
}

// NewServer constructs a dashboard server backed by the provided store.
func NewServer(store Store, logger *log.Logger) *Server {
	if logger == nil {
		logger = log.New(io.Discard, "dashboard-server", log.LstdFlags)
	}
	return &Server{store: store, logger: logger}
}

// Handler returns an http.Handler implementing the dashboard routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/records", s.handleRecords)
	mux.HandleFunc("/api/records/", s.handleRecord)
	mux.HandleFunc("/api/diff", s.handleDiff)
	return mux
}

// Run starts the HTTP server and blocks until the context is cancelled.
func (s *Server) Run(ctx context.Context, addr string) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		s.logger.Printf("dashboard listening on %s", addr)
		errCh <- srv.ListenAndServe()
	}()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return err
		}
		return nil
	case err := <-errCh:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.New("index").Parse(indexHTML))
	if err := tmpl.Execute(w, nil); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) handleRecords(w http.ResponseWriter, r *http.Request) {
	records, err := s.store.List(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.writeJSON(w, records)
}

func (s *Server) handleRecord(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/records/")
	if id == "" {
		http.NotFound(w, r)
		return
	}
	record, err := s.store.Get(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	summary, err := s.store.LoadSummary(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.writeJSON(w, struct {
		Record  Record         `json:"record"`
		Summary report.Summary `json:"summary"`
	}{Record: record, Summary: summary})
}

func (s *Server) handleDiff(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	current := query.Get("current")
	baseline := query.Get("baseline")
	if current == "" || baseline == "" {
		http.Error(w, "current and baseline parameters are required", http.StatusBadRequest)
		return
	}
	result, err := s.store.Diff(r.Context(), current, baseline)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.writeJSON(w, result)
}

func (s *Server) writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

const indexHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>Drone Firmware Analyzer Dashboard</title>
<style>
body { font-family: sans-serif; margin: 2rem; background: #f5f5f5; }
header { margin-bottom: 1.5rem; }
main { display: flex; gap: 2rem; }
section { background: #fff; padding: 1rem; border-radius: 8px; flex: 1; overflow: auto; max-height: 80vh; }
ul { list-style: none; padding: 0; }
li { margin-bottom: 0.5rem; cursor: pointer; }
li:hover { text-decoration: underline; }
pre { white-space: pre-wrap; word-break: break-word; }
label { display: block; margin-top: 0.5rem; }
select { width: 100%; }
</style>
</head>
<body>
<header>
<h1>Drone Firmware Analyzer Dashboard</h1>
<p>Browse historical analysis runs and compare firmware revisions.</p>
</header>
<main>
<section>
<h2>Runs</h2>
<ul id="runs"></ul>
</section>
<section>
<h2>Details</h2>
<div id="details">Select a run to view summary details.</div>
<label for="baseline">Compare with baseline:</label>
<select id="baseline"></select>
<pre id="diff"></pre>
</section>
</main>
<script>
async function loadRuns() {
  const res = await fetch('/api/records');
  const runs = await res.json();
  const list = document.getElementById('runs');
  const baseline = document.getElementById('baseline');
  list.innerHTML = '';
  baseline.innerHTML = '<option value="">-- none --</option>';
  runs.forEach(function(run) {
    const label = new Date(run.timestamp).toLocaleString() + ' — ' + run.firmware;
    const li = document.createElement('li');
    li.textContent = label;
    li.onclick = function() { showDetails(run.id); };
    list.appendChild(li);
    const option = document.createElement('option');
    option.value = run.id;
    option.textContent = label;
    baseline.appendChild(option);
  });
  baseline.onchange = function() { updateDiff(currentRecordId, baseline.value); };
}
let currentRecordId = '';
async function showDetails(id) {
  currentRecordId = id;
  const res = await fetch('/api/records/' + id);
  if (!res.ok) {
    document.getElementById('details').textContent = 'Failed to load run.';
    return;
  }
  const data = await res.json();
  const summary = data.summary;
  const record = data.record;
  const details = document.getElementById('details');
  const reports = [];
  ['markdown', 'html', 'json'].forEach(function(key) {
    const path = record.report_paths[key];
    if (path) {
      reports.push('<a href="file://' + path + '">' + key.toUpperCase() + '</a>');
    }
  });
  const reportHtml = reports.length > 0 ? reports.join('<br/>') : 'No reports generated.';
  details.innerHTML = '<h3>' + summary.firmware + '</h3>' +
    '<p><strong>Timestamp:</strong> ' + new Date(record.timestamp).toLocaleString() + '</p>' +
    '<p><strong>Duration:</strong> ' + record.duration + '</p>' +
    '<p><strong>Reports:</strong><br/>' + reportHtml + '</p>';
  updateDiff(id, document.getElementById('baseline').value);
}
async function updateDiff(current, baseline) {
  const diffEl = document.getElementById('diff');
  if (!current || !baseline) {
    diffEl.textContent = '';
    return;
  }
  const res = await fetch('/api/diff?current=' + encodeURIComponent(current) + '&baseline=' + encodeURIComponent(baseline));
  if (!res.ok) {
    diffEl.textContent = 'Failed to load diff.';
    return;
  }
  const data = await res.json();
  diffEl.textContent = JSON.stringify(data, null, 2);
}
loadRuns();
</script>
</body>
</html>`
