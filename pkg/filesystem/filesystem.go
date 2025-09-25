package filesystem

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// Mount represents a filesystem image or directory detected within an
// extracted firmware tree.
type Mount struct {
	ImagePath  string `json:"image_path"`
	MountPoint string `json:"mount_point"`
	Type       string `json:"type"`
	Size       int64  `json:"size"`
	Notes      string `json:"notes,omitempty"`
}

// Detector provides lightweight filesystem detection heuristics for common
// embedded formats without performing privileged mounts.
type Detector struct {
	logger   *log.Logger
	maxProbe int64
}

// NewDetector returns a Detector that probes up to 4MiB of each candidate file.
func NewDetector(logger *log.Logger) *Detector {
	if logger == nil {
		logger = log.New(io.Discard, "filesystem", log.LstdFlags)
	}
	return &Detector{logger: logger, maxProbe: 4 << 20}
}

// Detect walks the supplied root directory looking for filesystem images.
// Directories are treated as already extracted mounts and files are inspected
// for SquashFS, UBI and ext4 signatures.
func (d *Detector) Detect(ctx context.Context, root string) ([]Mount, error) {
	var mounts []Mount
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if entry.IsDir() {
			info, err := entry.Info()
			if err != nil {
				return err
			}
			mounts = append(mounts, Mount{
				ImagePath:  path,
				MountPoint: path,
				Type:       "directory",
				Size:       info.Size(),
			})
			return nil
		}

		info, err := entry.Info()
		if err != nil {
			return err
		}
		mntType, notes, err := d.classify(path)
		if err != nil {
			return err
		}
		if mntType == "" {
			return nil
		}
		mounts = append(mounts, Mount{
			ImagePath:  path,
			MountPoint: "",
			Type:       mntType,
			Size:       info.Size(),
			Notes:      notes,
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return mounts, nil
}

func (d *Detector) classify(path string) (string, string, error) {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".squashfs", ".sqsh":
		return "squashfs", "detected via file extension", nil
	case ".ubi":
		return "ubi", "detected via file extension", nil
	case ".ext", ".ext2", ".ext3", ".ext4":
		return "ext", "detected via file extension", nil
	}

	file, err := os.Open(path)
	if err != nil {
		return "", "", fmt.Errorf("open image: %w", err)
	}
	defer file.Close()

	magic := make([]byte, 4)
	if _, err := io.ReadFull(file, magic); err != nil {
		return "", "", nil
	}

	switch {
	case string(magic) == "hsqs" || string(magic) == "sqsh":
		return "squashfs", "magic matched", nil
	case string(magic) == "UBI#" || string(magic) == "UBI!":
		return "ubi", "magic matched", nil
	}

	// ext4 magic resides at offset 0x438
	if _, err := file.Seek(0x438, io.SeekStart); err != nil {
		return "", "", nil
	}
	var extMagic uint16
	if err := binary.Read(file, binary.LittleEndian, &extMagic); err != nil {
		return "", "", nil
	}
	if extMagic == 0xEF53 {
		return "ext", "magic matched", nil
	}
	return "", "", nil
}
