package xp3

import (
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

type Writer struct {
	file      *os.File
	w         io.WriteSeeker
	entries   []Entry
	filenames map[string]struct{}
	packed    bool
	closeFile bool
}

type AddFolderOptions struct {
	Flatten        bool
	EncryptionType string
	SaveTimestamps bool
	Logger         *slog.Logger
}

func CreateWriter(path string) (*Writer, error) {
	if err := mkdirParent(path); err != nil {
		return nil, err
	}
	file, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("create archive: %w", err)
	}
	writer, err := NewWriter(file)
	if err != nil {
		file.Close()
		return nil, err
	}
	writer.file = file
	writer.closeFile = true
	return writer, nil
}

func NewWriter(w io.WriteSeeker) (*Writer, error) {
	if _, err := w.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("seek archive start: %w", err)
	}
	if _, err := w.Write(signature); err != nil {
		return nil, fmt.Errorf("write signature: %w", err)
	}
	if err := binary.Write(w, binary.LittleEndian, uint64(0)); err != nil {
		return nil, fmt.Errorf("write index placeholder: %w", err)
	}
	return &Writer{
		w:         w,
		filenames: make(map[string]struct{}),
	}, nil
}

func (w *Writer) Close() error {
	var packErr error
	if !w.packed {
		packErr = w.Pack()
	}
	if w.closeFile && w.file != nil {
		if err := w.file.Close(); err != nil && packErr == nil {
			return err
		}
	}
	return packErr
}

func (w *Writer) AddFolder(root string, opts AddFolderOptions) error {
	if opts.EncryptionType == "" {
		opts.EncryptionType = EncryptionNone
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}

	return filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return fmt.Errorf("relative path for %q: %w", path, err)
		}
		internalPath := filepath.ToSlash(rel)
		if opts.Flatten {
			internalPath = filepath.Base(path)
		}
		if err := w.AddFile(path, internalPath, opts.EncryptionType, opts.SaveTimestamps); err != nil {
			return err
		}
		opts.Logger.Info("packed file", "path", internalPath)
		return nil
	})
}

func (w *Writer) AddFile(path string, internalPath string, encryptionType string, saveTimestamp bool) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read input file %q: %w", path, err)
	}
	if internalPath == "" {
		internalPath = filepath.Base(path)
	}
	internalPath, err = normalizeArchivePath(internalPath)
	if err != nil {
		return err
	}

	var timestamp uint64
	if saveTimestamp {
		stat, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("stat input file %q: %w", path, err)
		}
		timestamp = uint64(stat.ModTime().UnixMilli())
	}
	return w.Add(internalPath, data, encryptionType, timestamp)
}

func (w *Writer) Add(internalPath string, data []byte, encryptionType string, timestampMillis uint64) error {
	if w.packed {
		return ErrArchivePacked
	}
	if encryptionType == "" {
		encryptionType = EncryptionNone
	}
	var err error
	internalPath, err = normalizeArchivePath(internalPath)
	if err != nil {
		return err
	}
	if _, ok := w.filenames[internalPath]; ok {
		return fmt.Errorf("%w: %s", ErrDuplicateFile, internalPath)
	}
	if !IsEncryptionType(encryptionType) {
		return fmt.Errorf("%w: %s", ErrUnsupportedEncryption, encryptionType)
	}

	offset, err := w.w.Seek(0, io.SeekCurrent)
	if err != nil {
		return fmt.Errorf("get archive offset: %w", err)
	}
	entry, payload, err := makeEntry(internalPath, data, uint64(offset), encryptionType, timestampMillis)
	if err != nil {
		return err
	}
	if _, err := w.w.Write(payload); err != nil {
		return fmt.Errorf("write file payload %q: %w", internalPath, err)
	}
	w.entries = append(w.entries, entry)
	w.filenames[internalPath] = struct{}{}
	return nil
}

func (w *Writer) Pack() error {
	if w.packed {
		return nil
	}
	index, err := encodeIndex(w.entries)
	if err != nil {
		return err
	}
	offset, err := w.w.Seek(0, io.SeekCurrent)
	if err != nil {
		return fmt.Errorf("get index offset: %w", err)
	}
	if _, err := w.w.Write(index); err != nil {
		return fmt.Errorf("write file index: %w", err)
	}
	if _, err := w.w.Seek(int64(len(signature)), io.SeekStart); err != nil {
		return fmt.Errorf("seek index placeholder: %w", err)
	}
	if err := binary.Write(w.w, binary.LittleEndian, uint64(offset)); err != nil {
		return fmt.Errorf("write index offset: %w", err)
	}
	if _, err := w.w.Seek(0, io.SeekEnd); err != nil {
		return fmt.Errorf("seek archive end: %w", err)
	}
	w.packed = true
	return nil
}

func normalizeArchivePath(path string) (string, error) {
	path = filepath.ToSlash(filepath.Clean(path))
	path = strings.TrimPrefix(path, "./")
	if path == "." || path == "" || strings.HasPrefix(path, "../") || path == ".." || strings.HasPrefix(path, "/") {
		return "", fmt.Errorf("%w: %q", ErrUnsafePath, path)
	}
	return path, nil
}
