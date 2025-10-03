package sbom

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var errUnknownFormat = errors.New("unknown sbom format")

// Encode renders the supplied document using the requested format and returns
// the serialised bytes together with a recommended file extension. The
// extension does not include a leading dot.
func Encode(doc Document, format Format) ([]byte, string, error) {
	switch normaliseFormat(format) {
	case FormatSPDX, FormatSPDXJSON:
		copyDoc := doc
		copyDoc.Format = FormatSPDXJSON
		data, err := json.MarshalIndent(copyDoc, "", "  ")
		if err != nil {
			return nil, "", err
		}
		return data, "spdx.json", nil
	case FormatSPDXTagValue:
		copyDoc := doc
		copyDoc.Format = FormatSPDXTagValue
		return []byte(renderSPDXTagValue(copyDoc)), "spdx", nil
	case FormatCycloneDX:
		copyDoc := doc
		copyDoc.Format = FormatCycloneDX
		data, err := json.MarshalIndent(copyDoc, "", "  ")
		if err != nil {
			return nil, "", err
		}
		return data, "cdx.json", nil
	default:
		return nil, "", errUnknownFormat
	}
}

func renderSPDXTagValue(doc Document) string {
	var buf bytes.Buffer
	buf.WriteString("SPDXVersion: SPDX-2.3\n")
	buf.WriteString("DataLicense: CC0-1.0\n")
	buf.WriteString(fmt.Sprintf("DocumentName: %s\n", escapeTagValue(doc.Name)))
	buf.WriteString(fmt.Sprintf("SPDXID: SPDXRef-DOCUMENT\n"))
	buf.WriteString(fmt.Sprintf("DocumentNamespace: https://firmwareanalyzer.local/spdx/%s\n", sanitizeNamespace(doc.Name)))
	buf.WriteString("Creator: Tool: Drone Firmware Analyzer\n")
	buf.WriteString(fmt.Sprintf("Created: %s\n", doc.Created.Format("2006-01-02T15:04:05Z")))
	buf.WriteString("\n")

	for i, pkg := range doc.Packages {
		spdxID := fmt.Sprintf("SPDXRef-Package-%d", i+1)
		buf.WriteString(fmt.Sprintf("PackageName: %s\n", escapeTagValue(pkg.Name)))
		buf.WriteString(fmt.Sprintf("SPDXID: %s\n", spdxID))
		if pkg.Version != "" {
			buf.WriteString(fmt.Sprintf("PackageVersion: %s\n", escapeTagValue(pkg.Version)))
		}
		if pkg.Supplier != "" {
			buf.WriteString(fmt.Sprintf("PackageSupplier: %s\n", escapeTagValue(pkg.Supplier)))
		}
		if pkg.Path != "" {
			buf.WriteString(fmt.Sprintf("ExternalRef: OTHER location %s\n", escapeTagValue(pkg.Path)))
		}
		buf.WriteString("PackageDownloadLocation: NOASSERTION\n")
		buf.WriteString("FilesAnalyzed: false\n")
		buf.WriteString("PackageLicenseConcluded: NOASSERTION\n")
		buf.WriteString("PackageLicenseDeclared: NOASSERTION\n")
		buf.WriteString("PackageCopyrightText: NOASSERTION\n")
		buf.WriteString("\n")
	}

	if len(doc.Partitions) > 0 {
		buf.WriteString("# Partitions\n")
		sort.Slice(doc.Partitions, func(i, j int) bool {
			return doc.Partitions[i].Name < doc.Partitions[j].Name
		})
		for _, part := range doc.Partitions {
			buf.WriteString(fmt.Sprintf("## %s\n", escapeTagValue(part.Name)))
			buf.WriteString(fmt.Sprintf("Type: %s\n", escapeTagValue(part.Type)))
			if part.Path != "" {
				buf.WriteString(fmt.Sprintf("Path: %s\n", escapeTagValue(part.Path)))
			}
			if part.Size > 0 {
				buf.WriteString(fmt.Sprintf("Size: %d\n", part.Size))
			}
			if part.Offset > 0 {
				buf.WriteString(fmt.Sprintf("Offset: %d\n", part.Offset))
			}
			if part.Entropy > 0 {
				buf.WriteString(fmt.Sprintf("Entropy: %.2f\n", part.Entropy))
			}
			if part.Compression != "" {
				buf.WriteString(fmt.Sprintf("Compression: %s\n", escapeTagValue(part.Compression)))
			}
			if part.Notes != "" {
				buf.WriteString(fmt.Sprintf("Notes: %s\n", escapeTagValue(part.Notes)))
			}
			buf.WriteString("\n")
		}
	}

	return buf.String()
}

func escapeTagValue(value string) string {
	value = strings.ReplaceAll(value, "\n", " ")
	value = strings.ReplaceAll(value, "\r", " ")
	return value
}

func sanitizeNamespace(name string) string {
	cleaned := strings.ToLower(name)
	cleaned = strings.ReplaceAll(cleaned, " ", "-")
	cleaned = strings.ReplaceAll(cleaned, "_", "-")
	cleaned = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r
		case r >= '0' && r <= '9':
			return r
		case r == '-':
			return r
		default:
			return -1
		}
	}, cleaned)
	if cleaned == "" {
		cleaned = "document"
	}
	return cleaned
}

func normaliseFormat(format Format) Format {
	switch format {
	case FormatSPDX:
		return FormatSPDXJSON
	default:
		return format
	}
}

func writeFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func writeSignature(path string, signature []byte) error {
	if len(signature) == 0 {
		return nil
	}
	encoded := base64.StdEncoding.EncodeToString(signature)
	return writeFile(path, []byte(encoded))
}
