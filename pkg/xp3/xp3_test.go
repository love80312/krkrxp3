package xp3

import (
	"bytes"
	"encoding/binary"
	"errors"
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
