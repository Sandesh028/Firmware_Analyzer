package service

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// Service represents an init component discovered inside a firmware image.
type Service struct {
	Name     string   `json:"name"`
	Path     string   `json:"path"`
	Type     string   `json:"type"`
	Provides []string `json:"provides,omitempty"`
}

// Detector scans extracted filesystem trees for init systems, rc scripts and
// unit definitions to help build a runtime service inventory.
type Detector struct {
	logger *log.Logger
}

// NewDetector constructs a Detector. When logger is nil, logging is discarded.
func NewDetector(logger *log.Logger) *Detector {
	if logger == nil {
		logger = log.New(io.Discard, "service", log.LstdFlags)
	}
	return &Detector{logger: logger}
}

// Detect searches for SysV init scripts (etc/init.d), BusyBox rc directories,
// and systemd unit files within the provided root.
func (d *Detector) Detect(ctx context.Context, root string) ([]Service, error) {
	var services []Service

	visit := func(dir string, handler func(string, os.DirEntry) error) error {
		entries, err := os.ReadDir(dir)
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		for _, entry := range entries {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			if err := handler(filepath.Join(dir, entry.Name()), entry); err != nil {
				return err
			}
		}
		return nil
	}

	sysvDirs := []string{
		filepath.Join(root, "etc", "init.d"),
		filepath.Join(root, "etc", "rc.d"),
	}
	for _, dir := range sysvDirs {
		err := visit(dir, func(path string, entry os.DirEntry) error {
			if entry.IsDir() {
				return nil
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			if info.Mode()&0o111 == 0 {
				return nil
			}
			services = append(services, Service{
				Name: entry.Name(),
				Path: path,
				Type: "sysvinit",
			})
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	rcDirs := []string{
		filepath.Join(root, "etc", "rc.d"),
		filepath.Join(root, "etc", "init.d"),
	}
	for _, dir := range rcDirs {
		err := visit(dir, func(path string, entry os.DirEntry) error {
			if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
				return nil
			}
			if strings.HasPrefix(entry.Name(), "S") || strings.HasPrefix(entry.Name(), "K") {
				services = append(services, Service{
					Name: entry.Name(),
					Path: path,
					Type: "busybox-rc",
				})
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	unitDirs := []string{
		filepath.Join(root, "lib", "systemd", "system"),
		filepath.Join(root, "etc", "systemd", "system"),
	}
	for _, dir := range unitDirs {
		err := visit(dir, func(path string, entry os.DirEntry) error {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".service") {
				return nil
			}
			provides, err := parseProvides(path)
			if err != nil {
				return err
			}
			services = append(services, Service{
				Name:     strings.TrimSuffix(entry.Name(), ".service"),
				Path:     path,
				Type:     "systemd",
				Provides: provides,
			})
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	return services, nil
}

func parseProvides(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open unit: %w", err)
	}
	defer file.Close()

	var provides []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "provides=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				continue
			}
			value := strings.Trim(parts[1], "\"'")
			provides = append(provides, strings.FieldsFunc(value, func(r rune) bool {
				return r == ' ' || r == ','
			})...)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return provides, nil
}
