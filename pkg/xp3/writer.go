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
	file                *os.File
	w                   io.WriteSeeker
	entries             []Entry
	filenames           map[string]struct{}
	packed              bool
	closeFile           bool
	omitPathTerminators bool
}

type AddFolderOptions struct {
	Flatten             bool
	EncryptionType      string
	SaveTimestamps      bool
	OmitPathTerminators bool
	Logger              *slog.Logger
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

func (w *Writer) SetOmitPathTerminators(omit bool) {
	w.omitPathTerminators = omit
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
	w.SetOmitPathTerminators(opts.OmitPathTerminators)

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
	index, err := encodeIndex(w.entries, encodeOptions{
		OmitPathTerminators: w.omitPathTerminators,
	})
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

	if path == "." ||
		path == "" ||
		path == ".." ||
		strings.HasPrefix(path, "../") ||
		strings.Contains(path, "/../") ||
		strings.HasPrefix(path, "/") ||
		strings.Contains(path, "\x00") {
		return "", fmt.Errorf("%w: %q", ErrUnsafePath, path)
	}

	for _, part := range strings.Split(path, "/") {
		if part == "" || part == "." || part == ".." {
			return "", fmt.Errorf("%w: %q", ErrUnsafePath, path)
		}

		// Most Linux filesystems have NAME_MAX=255 bytes.
		// Leave some margin because encoded/non-ASCII names are byte-counted.
		if len(part) > 240 {
			return "", fmt.Errorf("%w: path component too long: %q", ErrUnsafePath, part)
		}
	}

	// Full relative archive path sanity cap.
	if len(path) > 1024 {
		return "", fmt.Errorf("%w: archive path too long: %q", ErrUnsafePath, path)
	}

	if isProtectedArchiveMarker(path) {
		return "", fmt.Errorf("%w: protected archive marker: %q", ErrUnsafePath, path)
	}

	return path, nil
}

func isProtectedArchiveMarker(path string) bool {
	base := filepath.Base(filepath.ToSlash(path))

	return strings.Contains(base, "This is a protected archive") ||
		strings.Contains(base, "Warning! Extracting this archive") ||
		strings.Contains(base, "著作者はこのアーカイブ") ||
		strings.Contains(base, "正規の利用方法以外") ||
		strings.Contains(base, "著作者の権利を侵害")
}

func safeOutputPath(outputDir, archivePath string) (string, error) {
	root, err := filepath.Abs(outputDir)
	if err != nil {
		return "", fmt.Errorf("resolve output dir: %w", err)
	}

	rel := filepath.FromSlash(archivePath)
	if filepath.IsAbs(rel) {
		return "", fmt.Errorf("%w: absolute archive path: %q", ErrUnsafePath, archivePath)
	}

	out := filepath.Join(root, rel)

	outAbs, err := filepath.Abs(out)
	if err != nil {
		return "", fmt.Errorf("resolve output path: %w", err)
	}

	if outAbs != root && !strings.HasPrefix(outAbs, root+string(filepath.Separator)) {
		return "", fmt.Errorf("%w: archive path escapes output dir: %q", ErrUnsafePath, archivePath)
	}

	return outAbs, nil
}
