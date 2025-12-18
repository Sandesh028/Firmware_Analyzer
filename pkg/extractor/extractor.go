package extractor

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"firmwareanalyzer/pkg/utils"
)

// Partition describes a logical filesystem extracted from a firmware image.
type Partition struct {
	Name        string  `json:"name"`
	Path        string  `json:"path"`
	Type        string  `json:"type"`
	Size        int64   `json:"size"`
	Offset      int64   `json:"offset,omitempty"`
	Notes       string  `json:"notes,omitempty"`
	Entropy     float64 `json:"entropy,omitempty"`
	Compression string  `json:"compression,omitempty"`
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
	WorkDir            string
	PreserveTemp       bool
	ExternalExtractors []string
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
	if opts.ExternalExtractors == nil {
		opts.ExternalExtractors = []string{"unblob", "binwalk"}
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
		var usedExternal bool
		usedExternal, err = e.tryExternal(ctx, firmwarePath, workDir)
		if err != nil {
			return nil, err
		}
		if !usedExternal {
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
	}

	root := normalizeRoot(workDir)
	res.OutputDir = root

	var partitions []Partition
	partitions, err = discoverPartitions(root)
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

func (e *Extractor) tryExternal(ctx context.Context, firmwarePath, outputDir string) (bool, error) {
	for _, tool := range e.opts.ExternalExtractors {
		if strings.TrimSpace(tool) == "" {
			continue
		}
		ok, err := e.runExternal(ctx, tool, firmwarePath, outputDir)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return false, err
			}
			e.logger.Printf("external extractor %s failed: %v", tool, err)
			continue
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

func (e *Extractor) runExternal(ctx context.Context, tool, firmwarePath, outputDir string) (bool, error) {
	if strings.TrimSpace(tool) == "" {
		return false, nil
	}
	path, err := exec.LookPath(tool)
	if err != nil {
		return false, nil
	}
	var args []string
	switch filepath.Base(path) {
	case "unblob":
		args = []string{"--extract-dir", outputDir, firmwarePath}
	case "binwalk":
		args = []string{"--extract", "--directory", outputDir, firmwarePath}
	default:
		return false, fmt.Errorf("unsupported external extractor: %s", tool)
	}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return false, fmt.Errorf("run %s: %w", tool, err)
	}
	return true, nil
}

func normalizeRoot(dir string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return dir
	}
	if len(entries) != 1 {
		return dir
	}
	entry := entries[0]
	if !entry.IsDir() {
		return dir
	}
	name := strings.ToLower(entry.Name())
	if strings.Contains(name, "extract") || strings.HasSuffix(name, "-root") || strings.HasSuffix(name, "_root") {
		return filepath.Join(dir, entry.Name())
	}
	return dir
}

func discoverPartitions(root string) ([]Partition, error) {
	var parts []Partition
	seenDirs := make(map[string]struct{})
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if d.IsDir() {
			if strings.Contains(rel, string(os.PathSeparator)) {
				return nil
			}
			if !utils.LooksLikeRoot(path) {
				return nil
			}
			if _, seen := seenDirs[rel]; seen {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			seenDirs[rel] = struct{}{}
			parts = append(parts, Partition{
				Name:        rel,
				Path:        path,
				Type:        "directory",
				Size:        info.Size(),
				Notes:       "contains system directories",
				Compression: "n/a",
			})
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return err
		}
		partType, offset, notes, err := classifyPartition(path)
		if err != nil {
			return err
		}
		if partType == "" {
			return nil
		}
		entropy, entropyErr := utils.SampleFileEntropy(path, 0)
		if entropyErr != nil {
			// Entropy calculation failures should not abort
			// partition discovery; surface the message in notes
			// for operator awareness.
			if notes == "" {
				notes = entropyErr.Error()
			} else {
				notes = notes + "; entropy: " + entropyErr.Error()
			}
			entropy = 0
		}
		parts = append(parts, Partition{
			Name:        rel,
			Path:        path,
			Type:        partType,
			Size:        info.Size(),
			Offset:      offset,
			Notes:       notes,
			Entropy:     entropy,
			Compression: compressionCategory(entropy),
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(parts, func(i, j int) bool { return parts[i].Name < parts[j].Name })
	return parts, nil
}

func compressionCategory(entropy float64) string {
	switch {
	case entropy == 0:
		return "unknown"
	case entropy >= 7.5:
		return "high"
	case entropy >= 6.0:
		return "medium"
	default:
		return "low"
	}
}

func classifyPartition(path string) (string, int64, string, error) {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".squashfs", ".sqsh":
		return "squashfs", 0, "detected via extension", nil
	case ".ubi":
		return "ubi", 0, "detected via extension", nil
	case ".ext", ".ext2", ".ext3", ".ext4":
		return "ext", 0, "detected via extension", nil
	}

	file, err := os.Open(path)
	if err != nil {
		return "", 0, "", fmt.Errorf("open partition: %w", err)
	}
	defer file.Close()

	header := make([]byte, 4)
	if _, err := io.ReadFull(file, header); err == nil {
		switch string(header) {
		case "hsqs", "sqsh":
			return "squashfs", 0, "magic matched", nil
		case "UBI#", "UBI!":
			return "ubi", 0, "magic matched", nil
		}
	}

	if _, err := file.Seek(0x438, io.SeekStart); err == nil {
		var extMagic uint16
		if err := binary.Read(file, binary.LittleEndian, &extMagic); err == nil && extMagic == 0xEF53 {
			return "ext", 0, "superblock magic matched", nil
		}
	}

	if ok, offset, notes, err := probeGPT(file); err != nil {
		return "", 0, "", err
	} else if ok {
		return "gpt", offset, notes, nil
	}

	if ok, notes, err := probeMTD(file); err != nil {
		return "", 0, "", err
	} else if ok {
		return "mtd", 0, notes, nil
	}

	return "", 0, "", nil
}

func probeGPT(file *os.File) (bool, int64, string, error) {
	if _, err := file.Seek(0, io.SeekEnd); err != nil {
		return false, 0, "", err
	}
	size, err := file.Seek(0, io.SeekCurrent)
	if err != nil {
		return false, 0, "", err
	}
	if size < 0x400 {
		return false, 0, "", nil
	}
	if _, err := file.Seek(0x200, io.SeekStart); err != nil {
		return false, 0, "", err
	}
	var header struct {
		Signature           [8]byte
		Revision            uint32
		HeaderSize          uint32
		CRC32               uint32
		Reserved            uint32
		CurrentLBA          uint64
		BackupLBA           uint64
		FirstUsableLBA      uint64
		LastUsableLBA       uint64
		DiskGUID            [16]byte
		PartitionEntryLBA   uint64
		NumPartitionEntries uint32
		PartitionEntrySize  uint32
		PartitionArrayCRC32 uint32
	}
	if err := binary.Read(file, binary.LittleEndian, &header); err != nil {
		return false, 0, "", nil
	}
	if !bytes.Equal(header.Signature[:], []byte("EFI PART")) {
		return false, 0, "", nil
	}
	entryOffset := int64(header.PartitionEntryLBA) * 512
	if entryOffset <= 0 {
		return true, 0, "GPT header detected", nil
	}
	if _, err := file.Seek(entryOffset, io.SeekStart); err != nil {
		return true, 0, "GPT header detected", nil
	}
	entrySize := int64(header.PartitionEntrySize)
	if entrySize < 32 {
		entrySize = 128
	}
	entry := make([]byte, entrySize)
	if _, err := io.ReadFull(file, entry); err != nil {
		return true, 0, "GPT header detected", nil
	}
	if bytes.Equal(entry[:16], make([]byte, 16)) {
		return true, 0, "GPT present without populated entries", nil
	}
	firstLBA := binary.LittleEndian.Uint64(entry[32:40])
	lastLBA := binary.LittleEndian.Uint64(entry[40:48])
	nameBytes := bytes.Trim(entry[56:], "\x00")
	name := strings.TrimSpace(string(nameBytes))
	if name == "" {
		name = "unnamed"
	}
	notes := fmt.Sprintf("GPT partition %s (%d-%d)", name, firstLBA, lastLBA)
	return true, int64(firstLBA) * 512, notes, nil
}

func probeMTD(file *os.File) (bool, string, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return false, "", err
	}
	buf := make([]byte, 64*1024)
	n, err := file.Read(buf)
	if err != nil && !errors.Is(err, io.EOF) {
		return false, "", err
	}
	buf = buf[:n]
	if bytes.Contains(buf, []byte("mtdparts=")) {
		return true, "contains mtdparts definition", nil
	}
	return false, "", nil
}
