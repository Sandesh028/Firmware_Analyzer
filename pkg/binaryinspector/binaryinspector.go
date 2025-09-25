package binaryinspector

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"

	"debug/elf"
)

// ErrNotELF is returned when the inspected file is not an ELF binary.
var ErrNotELF = errors.New("not an ELF binary")

// RELROLevel represents the strength of RELRO hardening applied to an ELF binary.
type RELROLevel string

const (
	// RELRONone indicates that the binary does not request RELRO protection.
	RELRONone RELROLevel = "none"
	// RELROPartial indicates that the binary has PT_GNU_RELRO but performs lazy binding.
	RELROPartial RELROLevel = "partial"
	// RELROFull indicates that the binary has PT_GNU_RELRO and enforces immediate binding.
	RELROFull RELROLevel = "full"
)

// Result holds hardening attributes detected for a single ELF binary.
type Result struct {
	Path         string     `json:"path"`
	Type         string     `json:"type"`
	Architecture string     `json:"architecture"`
	RELRO        RELROLevel `json:"relro"`
	NXEnabled    bool       `json:"nx_enabled"`
	PIEEnabled   bool       `json:"pie_enabled"`
	Stripped     bool       `json:"stripped"`
	Interpreter  string     `json:"interpreter,omitempty"`
	Err          string     `json:"error,omitempty"`
}

// MarkdownRow returns a Markdown formatted table row describing the binary.
func (r Result) MarkdownRow() string {
	status := func(b bool) string {
		if b {
			return "✅"
		}
		return "❌"
	}

	relro := strings.ToUpper(string(r.RELRO))
	if relro == "" {
		relro = "UNKNOWN"
	}

	stripped := "No"
	if r.Stripped {
		stripped = "Yes"
	}

	interpreter := r.Interpreter
	if interpreter == "" {
		interpreter = "-"
	}

	return fmt.Sprintf("| %s | %s | %s | %s | %s | %s | %s | %s |",
		r.Path, r.Type, r.Architecture, relro, status(r.NXEnabled), status(r.PIEEnabled), stripped, interpreter)
}

// Inspector analyses ELF binaries for common hardening flags.
type Inspector struct {
	logger *log.Logger
}

// NewInspector returns a new Inspector. If logger is nil, logging is discarded.
func NewInspector(logger *log.Logger) *Inspector {
	if logger == nil {
		logger = log.New(io.Discard, "binaryinspector", log.LstdFlags)
	}
	return &Inspector{logger: logger}
}

// Inspect walks the given root directory and inspects any ELF binaries found.
// The context allows the walk to be cancelled early. Any errors encountered
// during inspection are captured in the Result.Err field so that processing can
// continue for other binaries.
func (i *Inspector) Inspect(ctx context.Context, root string) ([]Result, error) {
	var results []Result
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if d.IsDir() {
			return nil
		}

		info, statErr := d.Info()
		if statErr != nil {
			return statErr
		}

		if !info.Mode().IsRegular() {
			return nil
		}

		res, inspectErr := i.inspectFile(path)
		switch {
		case errors.Is(inspectErr, ErrNotELF):
			return nil
		case inspectErr != nil:
			res.Err = inspectErr.Error()
			results = append(results, res)
		default:
			results = append(results, res)
		}
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}
	return results, nil
}

func (i *Inspector) inspectFile(path string) (Result, error) {
	file, err := os.Open(path)
	if err != nil {
		return Result{Path: path}, fmt.Errorf("open file: %w", err)
	}
	defer file.Close()

	header := make([]byte, 4)
	if _, err := io.ReadFull(file, header); err != nil {
		return Result{Path: path}, fmt.Errorf("read header: %w", err)
	}
	if !bytes.Equal(header, []byte(elf.ELFMAG)) {
		return Result{Path: path}, ErrNotELF
	}

	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return Result{Path: path}, fmt.Errorf("seek: %w", err)
	}

	ef, err := elf.NewFile(file)
	if err != nil {
		return Result{Path: path}, fmt.Errorf("parse ELF: %w", err)
	}
	defer ef.Close()

	result := Result{Path: path}

	result.Type = ef.FileHeader.Type.String()
	result.Architecture = ef.FileHeader.Machine.String()
	result.PIEEnabled = ef.FileHeader.Type == elf.ET_DYN
	result.NXEnabled = detectNX(ef)

	relro, relroErr := detectRELRO(ef)
	if relroErr != nil {
		return result, fmt.Errorf("detect RELRO: %w", relroErr)
	}
	result.RELRO = relro

	result.Stripped = isStripped(ef)
	result.Interpreter = interpreterPath(ef)

	return result, nil
}

func detectNX(f *elf.File) bool {
	for _, prog := range f.Progs {
		if prog.Type == elf.PT_GNU_STACK {
			return prog.Flags&elf.PF_X == 0
		}
	}
	return false
}

func detectRELRO(f *elf.File) (RELROLevel, error) {
	var hasRelro bool
	for _, prog := range f.Progs {
		if prog.Type == elf.PT_GNU_RELRO {
			hasRelro = true
			break
		}
	}
	if !hasRelro {
		return RELRONone, nil
	}

	tags, err := dynamicTags(f)
	if err != nil {
		return RELRONone, err
	}

	if val, ok := tags[elf.DT_BIND_NOW]; ok && val != 0 {
		return RELROFull, nil
	}
	if val, ok := tags[elf.DT_FLAGS]; ok && elf.DynFlag(val)&elf.DF_BIND_NOW != 0 {
		return RELROFull, nil
	}
	if val, ok := tags[elf.DT_FLAGS_1]; ok && elf.DynFlag1(val)&elf.DF_1_NOW != 0 {
		return RELROFull, nil
	}

	return RELROPartial, nil
}

func isStripped(f *elf.File) bool {
	symtab := f.Section(".symtab")
	if symtab == nil {
		return true
	}
	return symtab.Size == 0
}

func interpreterPath(f *elf.File) string {
	sec := f.Section(".interp")
	if sec == nil {
		return ""
	}

	data, err := sec.Data()
	if err != nil {
		return ""
	}

	return strings.TrimRight(string(data), "\x00")
}

func dynamicTags(f *elf.File) (map[elf.DynTag]uint64, error) {
	dynSec := f.Section(".dynamic")
	if dynSec == nil {
		return map[elf.DynTag]uint64{}, nil
	}

	data, err := dynSec.Data()
	if err != nil {
		return nil, err
	}

	tags := make(map[elf.DynTag]uint64)
	reader := bytes.NewReader(data)

	switch f.Class {
	case elf.ELFCLASS32:
		for {
			var entry elf.Dyn32
			if err := binary.Read(reader, f.ByteOrder, &entry); err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				return nil, err
			}
			if elf.DynTag(entry.Tag) == elf.DT_NULL {
				break
			}
			tags[elf.DynTag(entry.Tag)] = uint64(entry.Val)
		}
	case elf.ELFCLASS64:
		for {
			var entry elf.Dyn64
			if err := binary.Read(reader, f.ByteOrder, &entry); err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				return nil, err
			}
			if elf.DynTag(entry.Tag) == elf.DT_NULL {
				break
			}
			tags[elf.DynTag(entry.Tag)] = entry.Val
		}
	default:
		return nil, fmt.Errorf("unsupported ELF class: %s", f.Class)
	}

	return tags, nil
}

// CollectMarkdownTable renders results into a Markdown table body.
func CollectMarkdownTable(results []Result) string {
	if len(results) == 0 {
		return ""
	}

	var builder strings.Builder
	builder.WriteString("| Path | Type | Arch | RELRO | NX | PIE | Stripped | Interpreter |\n")
	builder.WriteString("| --- | --- | --- | --- | --- | --- | --- | --- |\n")
	for _, res := range results {
		builder.WriteString(res.MarkdownRow())
		builder.WriteByte('\n')
	}
	return builder.String()
}
