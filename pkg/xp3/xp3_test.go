package xp3

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestWriterReaderRoundTrip(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "test.xp3")

	writer, err := CreateWriter(archive)
	if err != nil {
		t.Fatalf("CreateWriter() error = %v", err)
	}
	if err := writer.Add("scripts/main.ks", []byte("hello xp3"), EncryptionNone, 0); err != nil {
		t.Fatalf("Add() error = %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	reader, err := OpenReader(archive)
	if err != nil {
		t.Fatalf("OpenReader() error = %v", err)
	}
	defer reader.Close()

	entries := reader.Entries()
	if len(entries) != 1 {
		t.Fatalf("len(entries) = %d, want 1", len(entries))
	}
	if entries[0].FilePath() != "scripts/main.ks" {
		t.Fatalf("FilePath() = %q", entries[0].FilePath())
	}

	file, err := os.Open(archive)
	if err != nil {
		t.Fatalf("open archive: %v", err)
	}
	defer file.Close()

	got, err := ReadEntry(file, entries[0], EncryptionNone, false)
	if err != nil {
		t.Fatalf("ReadEntry() error = %v", err)
	}
	if !bytes.Equal(got, []byte("hello xp3")) {
		t.Fatalf("ReadEntry() = %q", got)
	}
}

func TestEncryptedRoundTripRequiresEncryptionType(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "encrypted.xp3")

	writer, err := CreateWriter(archive)
	if err != nil {
		t.Fatalf("CreateWriter() error = %v", err)
	}
	if err := writer.Add("data.bin", []byte("secret"), "neko_vol0", 0); err != nil {
		t.Fatalf("Add() error = %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	reader, err := OpenReader(archive)
	if err != nil {
		t.Fatalf("OpenReader() error = %v", err)
	}
	defer reader.Close()

	entry := reader.Entries()[0]
	file, err := os.Open(archive)
	if err != nil {
		t.Fatalf("open archive: %v", err)
	}
	defer file.Close()

	if _, err := ReadEntry(file, entry, EncryptionNone, false); !errors.Is(err, ErrEncryptedFile) {
		t.Fatalf("ReadEntry() error = %v, want ErrEncryptedFile", err)
	}

	got, err := ReadEntry(file, entry, "neko_vol0", false)
	if err != nil {
		t.Fatalf("ReadEntry() encrypted error = %v", err)
	}
	if !bytes.Equal(got, []byte("secret")) {
		t.Fatalf("ReadEntry() = %q", got)
	}
}

func TestCanExtractPlainArchive(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "plain.xp3")

	writer, err := CreateWriter(archive)
	if err != nil {
		t.Fatalf("CreateWriter() error = %v", err)
	}
	if err := writer.Add("data.bin", []byte("plain"), EncryptionNone, 0); err != nil {
		t.Fatalf("Add() error = %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	check, err := CanExtract(archive, EncryptionNone)
	if err != nil {
		t.Fatalf("CanExtract() error = %v", err)
	}
	if !check.Extractable {
		t.Fatalf("CanExtract().Extractable = false, check = %+v", check)
	}
}

func TestCanExtractDetectsEncryptedArchive(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "encrypted.xp3")

	writer, err := CreateWriter(archive)
	if err != nil {
		t.Fatalf("CreateWriter() error = %v", err)
	}
	if err := writer.Add("data.bin", []byte("secret"), "neko_vol0", 0); err != nil {
		t.Fatalf("Add() error = %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	check, err := CanExtract(archive, EncryptionNone)
	if err != nil {
		t.Fatalf("CanExtract() error = %v", err)
	}
	if check.Extractable || !check.Encrypted || len(check.EncryptedPaths) != 1 {
		t.Fatalf("CanExtract() = %+v, want encrypted and not extractable", check)
	}

	check, err = CanExtract(archive, "neko_vol0")
	if err != nil {
		t.Fatalf("CanExtract() with encryption error = %v", err)
	}
	if !check.Extractable || check.Encrypted {
		t.Fatalf("CanExtract() with encryption = %+v, want extractable", check)
	}
}

func TestCanExtractDetectsProtectedArchiveMarker(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "protected.xp3")
	protectedPath := "This is a protected archive.txt"
	writeSingleEntryArchive(t, archive, protectedPath, []byte("warning"))

	check, err := CanExtract(archive, EncryptionNone)
	if err != nil {
		t.Fatalf("CanExtract() error = %v", err)
	}
	if check.Extractable || !check.Protected || len(check.ProtectedPaths) != 1 {
		t.Fatalf("CanExtract() = %+v, want protected and not extractable", check)
	}
	if check.ProtectedPaths[0] != protectedPath {
		t.Fatalf("ProtectedPaths[0] = %q, want %q", check.ProtectedPaths[0], protectedPath)
	}
}

func TestAddFolderAndExtractAll(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "input")
	if err := os.MkdirAll(filepath.Join(input, "sub"), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(input, "sub", "file.txt"), []byte("content"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	archive := filepath.Join(dir, "archive.xp3")
	writer, err := CreateWriter(archive)
	if err != nil {
		t.Fatalf("CreateWriter() error = %v", err)
	}
	if err := writer.AddFolder(input, AddFolderOptions{EncryptionType: EncryptionNone}); err != nil {
		t.Fatalf("AddFolder() error = %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	reader, err := OpenReader(archive)
	if err != nil {
		t.Fatalf("OpenReader() error = %v", err)
	}
	defer reader.Close()

	output := filepath.Join(dir, "output")
	if err := reader.ExtractAll(output, ExtractOptions{EncryptionType: EncryptionNone}); err != nil {
		t.Fatalf("ExtractAll() error = %v", err)
	}
	got, err := os.ReadFile(filepath.Join(output, "sub", "file.txt"))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !bytes.Equal(got, []byte("content")) {
		t.Fatalf("extracted content = %q", got)
	}
}

func TestUnsafeArchivePathRejected(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "test.xp3")
	writer, err := CreateWriter(archive)
	if err != nil {
		t.Fatalf("CreateWriter() error = %v", err)
	}
	defer writer.Close()

	if err := writer.Add("../escape.txt", []byte("nope"), EncryptionNone, 0); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("Add() error = %v, want ErrUnsafePath", err)
	}
}

func TestReadInfoWithoutNullTerminator(t *testing.T) {
	var index bytes.Buffer
	index.WriteString("File")
	binary.Write(&index, binary.LittleEndian, uint64(86))
	index.WriteString("info")
	binary.Write(&index, binary.LittleEndian, uint64(28))
	binary.Write(&index, binary.LittleEndian, uint32(0))
	binary.Write(&index, binary.LittleEndian, uint64(12))
	binary.Write(&index, binary.LittleEndian, uint64(12))
	binary.Write(&index, binary.LittleEndian, uint16(3))
	index.Write(utf16LEBytes("a/b"))
	index.WriteString("segm")
	binary.Write(&index, binary.LittleEndian, uint64(28))
	index.Write([]byte{0, 0, 0, 0})
	binary.Write(&index, binary.LittleEndian, uint64(19))
	binary.Write(&index, binary.LittleEndian, uint64(12))
	binary.Write(&index, binary.LittleEndian, uint64(12))
	index.WriteString("adlr")
	binary.Write(&index, binary.LittleEndian, uint64(4))
	binary.Write(&index, binary.LittleEndian, uint32(0x12345678))

	entries, err := parseEntries(index.Bytes())
	if err != nil {
		t.Fatalf("parseEntries() error = %v", err)
	}
	if got := entries[0].FilePath(); got != "a/b" {
		t.Fatalf("FilePath() = %q", got)
	}
}

func TestEncodeIndexCanOmitPathTerminators(t *testing.T) {
	entry, _, err := makeEntry("bgimage/ABOUT.png", []byte("content"), uint64(len(signature)+8), EncryptionNone, 0)
	if err != nil {
		t.Fatalf("makeEntry() error = %v", err)
	}

	withTerminator, err := encodeIndex([]Entry{entry}, encodeOptions{})
	if err != nil {
		t.Fatalf("encodeIndex() with terminator error = %v", err)
	}
	withoutTerminator, err := encodeIndex([]Entry{entry}, encodeOptions{OmitPathTerminators: true})
	if err != nil {
		t.Fatalf("encodeIndex() without terminator error = %v", err)
	}

	withEntry := mustParseSingleEntry(t, indexPayload(t, withTerminator))
	withoutEntry := mustParseSingleEntry(t, indexPayload(t, withoutTerminator))

	if withEntry.FilePath() != withoutEntry.FilePath() {
		t.Fatalf("paths differ: %q != %q", withEntry.FilePath(), withoutEntry.FilePath())
	}
	if got := infoChunkSize(t, indexPayload(t, withTerminator)); got != 58 {
		t.Fatalf("terminated info chunk size = %d, want 58", got)
	}
	if got := infoChunkSize(t, indexPayload(t, withoutTerminator)); got != 56 {
		t.Fatalf("unterminated info chunk size = %d, want 56", got)
	}
}

func TestReaderRecommendsOmittingPathTerminators(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "unterminated.xp3")
	writer, err := CreateWriter(archive)
	if err != nil {
		t.Fatalf("CreateWriter() error = %v", err)
	}
	writer.SetOmitPathTerminators(true)
	if err := writer.Add("bgimage/ABOUT.png", []byte("content"), EncryptionNone, 0); err != nil {
		t.Fatalf("Add() error = %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	reader, err := OpenReader(archive)
	if err != nil {
		t.Fatalf("OpenReader() error = %v", err)
	}
	defer reader.Close()

	if !reader.OmitPathTerminatorsRecommended() {
		t.Fatal("OmitPathTerminatorsRecommended() = false, want true")
	}
}

func writeSingleEntryArchive(t *testing.T, archive string, internalPath string, data []byte) {
	t.Helper()

	entry, payload, err := makeEntry(internalPath, data, uint64(len(signature)+8), EncryptionNone, 0)
	if err != nil {
		t.Fatalf("makeEntry() error = %v", err)
	}
	index, err := encodeIndex([]Entry{entry}, encodeOptions{})
	if err != nil {
		t.Fatalf("encodeIndex() error = %v", err)
	}

	file, err := os.Create(archive)
	if err != nil {
		t.Fatalf("create archive: %v", err)
	}
	defer file.Close()

	if _, err := file.Write(signature); err != nil {
		t.Fatalf("write signature: %v", err)
	}
	if err := binary.Write(file, binary.LittleEndian, uint64(0)); err != nil {
		t.Fatalf("write index placeholder: %v", err)
	}
	if _, err := file.Write(payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	indexOffset := uint64(len(signature) + 8 + len(payload))
	if _, err := file.Write(index); err != nil {
		t.Fatalf("write index: %v", err)
	}
	if _, err := file.Seek(int64(len(signature)), io.SeekStart); err != nil {
		t.Fatalf("seek index placeholder: %v", err)
	}
	if err := binary.Write(file, binary.LittleEndian, indexOffset); err != nil {
		t.Fatalf("write index offset: %v", err)
	}
}

func indexPayload(t *testing.T, index []byte) []byte {
	t.Helper()
	if len(index) < 9 {
		t.Fatalf("index too short: %d", len(index))
	}
	switch index[0] {
	case indexUncompressed:
		size := binary.LittleEndian.Uint64(index[1:9])
		if int(size) != len(index)-9 {
			t.Fatalf("index payload size = %d, want %d", size, len(index)-9)
		}
		return index[9:]
	case indexCompressed:
		if len(index) < 17 {
			t.Fatalf("compressed index too short: %d", len(index))
		}
		compressedSize := binary.LittleEndian.Uint64(index[1:9])
		uncompressedSize := binary.LittleEndian.Uint64(index[9:17])
		if int(compressedSize) != len(index)-17 {
			t.Fatalf("compressed payload size = %d, want %d", compressedSize, len(index)-17)
		}
		zr, err := zlib.NewReader(bytes.NewReader(index[17:]))
		if err != nil {
			t.Fatalf("zlib.NewReader() error = %v", err)
		}
		defer zr.Close()
		payload, err := io.ReadAll(zr)
		if err != nil {
			t.Fatalf("ReadAll() error = %v", err)
		}
		if uint64(len(payload)) != uncompressedSize {
			t.Fatalf("uncompressed payload size = %d, want %d", len(payload), uncompressedSize)
		}
		return payload
	default:
		t.Fatalf("unexpected index flag: 0x%02x", index[0])
		return nil
	}
}

func mustParseSingleEntry(t *testing.T, payload []byte) Entry {
	t.Helper()
	entries, err := parseEntries(payload)
	if err != nil {
		t.Fatalf("parseEntries() error = %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("len(entries) = %d, want 1", len(entries))
	}
	return entries[0]
}

func infoChunkSize(t *testing.T, payload []byte) uint64 {
	t.Helper()
	offset := bytes.Index(payload, []byte("info"))
	if offset < 0 {
		t.Fatal("info chunk not found")
	}
	return binary.LittleEndian.Uint64(payload[offset+4 : offset+12])
}
