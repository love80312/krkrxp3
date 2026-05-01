package xp3

import (
	"bytes"
	"errors"
	"fmt"
	"hash/adler32"
	"io"
	"log/slog"
	"os"
	"path/filepath"
)

type Reader struct {
	file     *os.File
	entries  []Entry
	rawIndex []byte
}

type ExtractOptions struct {
	EncryptionType string
	Raw            bool
	Logger         *slog.Logger
}

func OpenReader(path string) (*Reader, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open archive: %w", err)
	}

	reader, err := NewReader(file)
	if err != nil {
		file.Close()
		return nil, err
	}
	reader.file = file
	return reader, nil
}

func NewReader(rs io.ReadSeeker) (*Reader, error) {
	header := make([]byte, len(signature))
	if _, err := io.ReadFull(rs, header); err != nil {
		return nil, fmt.Errorf("read signature: %w", err)
	}
	if !bytes.Equal(header, signature) {
		return nil, ErrInvalidArchive
	}

	rawIndex, err := readIndex(rs)
	if err != nil {
		return nil, err
	}
	entries, err := parseEntries(rawIndex)
	if err != nil {
		return nil, err
	}

	return &Reader{entries: entries, rawIndex: rawIndex}, nil
}

func (r *Reader) Close() error {
	if r.file == nil {
		return nil
	}
	return r.file.Close()
}

func (r *Reader) Entries() []Entry {
	return append([]Entry(nil), r.entries...)
}

func (r *Reader) OmitPathTerminatorsRecommended() bool {
	return countUnterminatedPaths(r.entries) > 0
}

func (r *Reader) DumpIndex(path string) error {
	if err := mkdirParent(path); err != nil {
		return err
	}
	return os.WriteFile(path, r.rawIndex, 0o644)
}

func (r *Reader) ExtractAll(outputDir string, opts ExtractOptions) error {
	if opts.EncryptionType == "" {
		opts.EncryptionType = EncryptionNone
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if count := countUnterminatedPaths(r.entries); count > 0 {
		opts.Logger.Info("[omit-null-term] archive index has UTF-16 path chunks without null terminators; use --omit-path-terminators when repacking to match this layout", "entries", count)
	}

	for _, entry := range r.entries {
		if r.file == nil {
			return errors.New("reader was not opened from a file")
		}
		data, err := ReadEntry(r.file, entry, opts.EncryptionType, opts.Raw)
		if err != nil {
			return fmt.Errorf("read %q: %w", entry.FilePath(), err)
		}
		if checksum := adler32.Checksum(data); checksum != entry.Adler.Value && !opts.Raw {
			return fmt.Errorf("%w for %q: got %08x want %08x", ErrChecksumMismatch, entry.FilePath(), checksum, entry.Adler.Value)
		}

		archivePath, err := normalizeArchivePath(entry.FilePath())
		if err != nil {
			return err
		}
		outPath := filepath.Join(outputDir, filepath.FromSlash(archivePath))
		if err := mkdirParent(outPath); err != nil {
			return err
		}
		if err := os.WriteFile(outPath, data, 0o644); err != nil {
			return fmt.Errorf("write %q: %w", outPath, err)
		}
		opts.Logger.Info("extracted file", "path", entry.FilePath(), "compressed_bytes", entry.CompressedSize(), "uncompressed_bytes", entry.UncompressedSize())
	}
	return nil
}

func ReadEntry(rs io.ReadSeeker, entry Entry, encryptionType string, raw bool) ([]byte, error) {
	if entry.IsEncrypted() && (encryptionType == "" || encryptionType == EncryptionNone) && !raw {
		return nil, ErrEncryptedFile
	}

	var out []byte
	for _, segment := range entry.Segments {
		if _, err := rs.Seek(int64(segment.Offset), io.SeekStart); err != nil {
			return nil, fmt.Errorf("seek segment: %w", err)
		}
		data := make([]byte, segment.CompressedSize)
		if _, err := io.ReadFull(rs, data); err != nil {
			return nil, fmt.Errorf("read segment: %w", err)
		}
		if segment.IsCompressed {
			decompressed, err := decompress(data)
			if err != nil {
				return nil, fmt.Errorf("decompress segment: %w", err)
			}
			data = decompressed
		}
		if uint64(len(data)) != segment.UncompressedSize {
			return nil, fmt.Errorf("%w: segment size got %d want %d", ErrInvalidArchive, len(data), segment.UncompressedSize)
		}
		if entry.IsEncrypted() && !raw {
			decrypted, err := xorData(data, entry.Adler.Value, encryptionType)
			if err != nil {
				return nil, err
			}
			data = decrypted
		}
		out = append(out, data...)
	}
	return out, nil
}

func countUnterminatedPaths(entries []Entry) int {
	var count int
	for _, entry := range entries {
		if !entry.Info.PathTerminated {
			count++
			continue
		}
		if entry.Encryption != nil && !entry.Encryption.PathTerminated {
			count++
		}
	}
	return count
}

func mkdirParent(path string) error {
	dir := filepath.Dir(path)
	if dir == "." || dir == "" {
		return nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create directory %q: %w", dir, err)
	}
	return nil
}
