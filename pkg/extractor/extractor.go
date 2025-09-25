package extractor

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Partition describes a logical filesystem extracted from a firmware image.
type Partition struct {
	Name string `json:"name"`
	Path string `json:"path"`
	Type string `json:"type"`
	Size int64  `json:"size"`
}

// Result holds metadata about an extraction run.
type Result struct {
	Firmware   string      `json:"firmware"`
	OutputDir  string      `json:"output_dir"`
	Started    time.Time   `json:"started"`
	Completed  time.Time   `json:"completed"`
	Partitions []Partition `json:"partitions"`
}

// Options configure the Extractor behaviour.
type Options struct {
	WorkDir      string
	PreserveTemp bool
}

// Extractor performs firmware extraction using built-in archive handlers and
// optional external tooling.
type Extractor struct {
	opts   Options
	logger *log.Logger
}

// New creates an Extractor with the supplied options. If logger is nil it is
// replaced with a silent logger.
func New(opts Options, logger *log.Logger) *Extractor {
	if logger == nil {
		logger = log.New(io.Discard, "extractor", log.LstdFlags)
	}
	return &Extractor{opts: opts, logger: logger}
}

// Extract expands the supplied firmware image into a working directory and
// returns metadata about any detected partitions. The function supports
// tarballs (optionally gzip compressed), zip archives, and already extracted
// directory trees.
func (e *Extractor) Extract(ctx context.Context, firmwarePath string) (*Result, error) {
	info, err := os.Stat(firmwarePath)
	if err != nil {
		return nil, fmt.Errorf("stat firmware: %w", err)
	}

	workDir := e.opts.WorkDir
	if workDir == "" {
		workDir, err = os.MkdirTemp("", "fw-extract-*")
		if err != nil {
			return nil, fmt.Errorf("create temp dir: %w", err)
		}
	} else {
		if err := os.MkdirAll(workDir, 0o755); err != nil {
			return nil, fmt.Errorf("create workdir: %w", err)
		}
		workDir, err = os.MkdirTemp(workDir, "fw-")
		if err != nil {
			return nil, fmt.Errorf("create nested temp dir: %w", err)
		}
	}

	res := &Result{
		Firmware:  firmwarePath,
		OutputDir: workDir,
		Started:   time.Now(),
	}

	cleanup := func() {
		if e.opts.PreserveTemp {
			return
		}
		if err != nil {
			_ = os.RemoveAll(workDir)
		}
	}
	defer cleanup()

	switch {
	case info.IsDir():
		if err = copyDir(ctx, firmwarePath, workDir); err != nil {
			return nil, err
		}
	default:
		ext := strings.ToLower(filepath.Ext(info.Name()))
		switch ext {
		case ".gz", ".tgz", ".tar":
			if err = extractTar(ctx, firmwarePath, workDir); err != nil {
				return nil, err
			}
		case ".zip":
			if err = extractZip(ctx, firmwarePath, workDir); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("unsupported firmware format: %s", firmwarePath)
		}
	}

	var partitions []Partition
	partitions, err = discoverPartitions(workDir)
	if err != nil {
		return nil, err
	}
	res.Partitions = partitions
	res.Completed = time.Now()
	return res, nil
}

func copyDir(ctx context.Context, src, dst string) error {
	return filepath.WalkDir(src, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}

		info, err := d.Info()
		if err != nil {
			return err
		}

		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}

		in, err := os.Open(path)
		if err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode())
		if err != nil {
			in.Close()
			return err
		}
		if _, err := io.Copy(out, in); err != nil {
			out.Close()
			in.Close()
			return err
		}
		out.Close()
		in.Close()
		return nil
	})
}

func extractTar(ctx context.Context, src, dst string) error {
	file, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open tar: %w", err)
	}
	defer file.Close()

	var reader io.Reader = file
	lower := strings.ToLower(src)
	if strings.HasSuffix(lower, ".gz") || strings.HasSuffix(lower, ".tgz") {
		gz, err := gzip.NewReader(file)
		if err != nil {
			return fmt.Errorf("gzip reader: %w", err)
		}
		defer gz.Close()
		reader = gz
	}

	tarReader := tar.NewReader(reader)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("tar next: %w", err)
		}
		target := filepath.Join(dst, header.Name)
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.FileMode(header.Mode)); err != nil {
				return fmt.Errorf("mkdir %s: %w", target, err)
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(header.Mode))
			if err != nil {
				return fmt.Errorf("create %s: %w", target, err)
			}
			if _, err := io.Copy(out, tarReader); err != nil {
				out.Close()
				return fmt.Errorf("copy %s: %w", target, err)
			}
			out.Close()
		}
	}
	return nil
}

func extractZip(ctx context.Context, src, dst string) error {
	reader, err := zip.OpenReader(src)
	if err != nil {
		return fmt.Errorf("open zip: %w", err)
	}
	defer reader.Close()

	for _, file := range reader.File {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		target := filepath.Join(dst, file.Name)
		if file.FileInfo().IsDir() {
			if err := os.MkdirAll(target, file.Mode()); err != nil {
				return err
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}

		rc, err := file.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, file.Mode())
		if err != nil {
			rc.Close()
			return err
		}
		if _, err := io.Copy(out, rc); err != nil {
			out.Close()
			rc.Close()
			return err
		}
		out.Close()
		rc.Close()
	}

	return nil
}

func discoverPartitions(root string) ([]Partition, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("read extracted root: %w", err)
	}

	var parts []Partition
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		partType := "file"
		if entry.IsDir() {
			partType = "directory"
		} else {
			switch strings.ToLower(filepath.Ext(entry.Name())) {
			case ".squashfs", ".sqsh":
				partType = "squashfs"
			case ".ubi":
				partType = "ubi"
			case ".ext", ".ext2", ".ext3", ".ext4":
				partType = "ext"
			}
		}
		parts = append(parts, Partition{
			Name: entry.Name(),
			Path: filepath.Join(root, entry.Name()),
			Type: partType,
			Size: info.Size(),
		})
	}
	return parts, nil
}
