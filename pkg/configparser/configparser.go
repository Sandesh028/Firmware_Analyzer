package configparser

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"firmwareanalyzer/pkg/utils"
)

// Parameter represents a flattened configuration entry discovered within a
// parsed configuration file.
type Parameter struct {
	Key        string `json:"key"`
	Value      string `json:"value"`
	Credential bool   `json:"credential"`
}

// Finding groups the parameters produced from parsing a single configuration
// file.
type Finding struct {
	File   string      `json:"file"`
	Format string      `json:"format"`
	Params []Parameter `json:"parameters"`
}

// Parser loads configuration files from extracted firmware directories and
// normalises them into flattened key/value pairs for downstream analysis.
type Parser struct {
	maxSize int64
	logger  *log.Logger
}

// NewParser instantiates a Parser with sane defaults.
func NewParser(logger *log.Logger) *Parser {
	if logger == nil {
		logger = log.New(io.Discard, "configparser", log.LstdFlags)
	}
	return &Parser{maxSize: 2 << 20, logger: logger}
}

// Parse walks the provided root directory collecting configuration findings
// for supported formats (JSON, XML, TOML, and INI).
func (p *Parser) Parse(ctx context.Context, root string) ([]Finding, error) {
	var findings []Finding
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		format := detectFormat(path)
		if format == "" {
			return nil
		}
		finding, err := p.parseFile(path, format)
		if err != nil {
			return err
		}
		if len(finding.Params) > 0 {
			findings = append(findings, finding)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return findings, nil
}

func (p *Parser) parseFile(path, format string) (Finding, error) {
	info, err := os.Stat(path)
	if err != nil {
		return Finding{}, fmt.Errorf("stat config: %w", err)
	}
	if info.Size() > p.maxSize {
		return Finding{}, fmt.Errorf("config file too large: %s", path)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return Finding{}, fmt.Errorf("read config: %w", err)
	}

	var flat map[string]string
	switch format {
	case "json":
		var v any
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.UseNumber()
		if err := dec.Decode(&v); err != nil {
			return Finding{}, fmt.Errorf("parse json: %w", err)
		}
		flat = utils.Flatten("", v)
	case "xml":
		flat, err = parseXML(data)
		if err != nil {
			return Finding{}, err
		}
	case "toml":
		flat = parseSimpleKV(data)
	case "ini":
		flat = parseINI(data)
	default:
		return Finding{}, fmt.Errorf("unsupported format %s", format)
	}

	params := make([]Parameter, 0, len(flat))
	for k, v := range flat {
		params = append(params, Parameter{
			Key:        k,
			Value:      v,
			Credential: utils.ContainsCredentialKeyword(k),
		})
	}
	sort.Slice(params, func(i, j int) bool { return params[i].Key < params[j].Key })

	return Finding{File: path, Format: format, Params: params}, nil
}

func detectFormat(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		return "json"
	case ".xml":
		return "xml"
	case ".toml":
		return "toml"
	case ".ini", ".conf":
		return "ini"
	default:
		return ""
	}
}

func parseXML(data []byte) (map[string]string, error) {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	decoder.CharsetReader = func(encoding string, input io.Reader) (io.Reader, error) {
		return input, nil
	}

	flat := make(map[string]string)
	var stack []string
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("parse xml: %w", err)
		}
		switch tok := token.(type) {
		case xml.StartElement:
			stack = append(stack, tok.Name.Local)
			for _, attr := range tok.Attr {
				key := strings.Join(append(stack, "@"+attr.Name.Local), ".")
				flat[key] = attr.Value
			}
		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		case xml.CharData:
			text := strings.TrimSpace(string(tok))
			if text == "" {
				continue
			}
			key := strings.Join(stack, ".")
			flat[key] = text
		}
	}
	return flat, nil
}

func parseSimpleKV(data []byte) map[string]string {
	flat := make(map[string]string)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	var prefix string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			prefix = strings.Trim(line, "[]")
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.Trim(strings.TrimSpace(parts[1]), "\"'")
		if prefix != "" {
			key = prefix + "." + key
		}
		flat[key] = value
	}
	return flat
}

func parseINI(data []byte) map[string]string {
	flat := make(map[string]string)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	var section string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.Trim(line, "[]")
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.Trim(strings.TrimSpace(parts[1]), "\"'")
		if section != "" {
			key = section + "." + key
		}
		flat[key] = value
	}
	return flat
}
