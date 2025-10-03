package filesystem

import (
	"bytes"
	"context"
	"encoding/binary"
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

// Mount represents a filesystem image or directory detected within an
// extracted firmware tree.
type Mount struct {
	ImagePath  string `json:"image_path"`
	MountPoint string `json:"mount_point"`
	Type       string `json:"type"`
	Size       int64  `json:"size"`
	Offset     int64  `json:"offset,omitempty"`
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
		if path == root {
			return nil
		}
		if entry.IsDir() {
			if !utils.LooksLikeRoot(path) {
				return nil
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			mounts = append(mounts, Mount{
				ImagePath:  path,
				MountPoint: path,
				Type:       "directory",
				Size:       info.Size(),
				Notes:      "contains system directories",
			})
			return nil
		}

		info, err := entry.Info()
		if err != nil {
			return err
		}
		mntType, notes, offset, err := d.classify(path)
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
			Offset:     offset,
			Notes:      notes,
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(mounts, func(i, j int) bool { return mounts[i].ImagePath < mounts[j].ImagePath })
	return mounts, nil
}

func (d *Detector) classify(path string) (string, string, int64, error) {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".squashfs", ".sqsh":
		return "squashfs", "detected via file extension", 0, nil
	case ".ubi":
		return "ubi", "detected via file extension", 0, nil
	case ".ext", ".ext2", ".ext3", ".ext4":
		return "ext", "detected via file extension", 0, nil
	}

	file, err := os.Open(path)
	if err != nil {
		return "", "", 0, fmt.Errorf("open image: %w", err)
	}
	defer file.Close()

	magic := make([]byte, 4)
	if _, err := io.ReadFull(file, magic); err != nil {
		return "", "", 0, nil
	}

	switch {
	case string(magic) == "hsqs" || string(magic) == "sqsh":
		return "squashfs", "magic matched", 0, nil
	case string(magic) == "UBI#" || string(magic) == "UBI!":
		return "ubi", "magic matched", 0, nil
	}

	// ext4 magic resides at offset 0x438
	if _, err := file.Seek(0x438, io.SeekStart); err == nil {
		var extMagic uint16
		if err := binary.Read(file, binary.LittleEndian, &extMagic); err == nil && extMagic == 0xEF53 {
			return "ext", "magic matched", 0, nil
		}
	}
	if ok, offset, notes, err := probeGPT(file); err != nil {
		return "", "", 0, err
	} else if ok {
		return "gpt", notes, offset, nil
	}
	if ok, notes, err := probeMTD(file, d.maxProbe); err != nil {
		return "", "", 0, err
	} else if ok {
		return "mtd", notes, 0, nil
	}
	return "", "", 0, nil
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
	if len(entry) < 56 {
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

func probeMTD(file *os.File, max int64) (bool, string, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return false, "", err
	}
	bufSize := max
	if bufSize <= 0 || bufSize > 64*1024 {
		bufSize = 64 * 1024
	}
	buf := make([]byte, bufSize)
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
