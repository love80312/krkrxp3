package xp3

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"hash/adler32"
	"io"
)

var signature = []byte{'X', 'P', '3', 0x0D, 0x0A, 0x20, 0x0A, 0x1A, 0x8B, 0x67, 0x01}

const (
	indexContinue     byte   = 0x80
	indexCompressed   byte   = 0x01
	indexUncompressed byte   = 0x00
	fileIsEncrypted   uint32 = 1 << 31
)

type Entry struct {
	Encryption *Encryption
	Time       FileTime
	Adler      Adler
	Segments   []Segment
	Info       Info
}

type Encryption struct {
	ChunkName      [4]byte
	Adler32        uint32
	FilePath       string
	PathTerminated bool
}

type FileTime struct {
	TimestampMillis uint64
}

type Adler struct {
	Value uint32
}

type Segment struct {
	IsCompressed     bool
	Offset           uint64
	UncompressedSize uint64
	CompressedSize   uint64
}

type Info struct {
	IsEncrypted      bool
	UncompressedSize uint64
	CompressedSize   uint64
	FilePath         string
	PathTerminated   bool
}

func (e Entry) FilePath() string {
	if e.Encryption != nil {
		return e.Encryption.FilePath
	}
	return e.Info.FilePath
}

func (e Entry) IsEncrypted() bool {
	return e.Encryption != nil || e.Info.IsEncrypted
}

func (e Entry) UncompressedSize() uint64 {
	var total uint64
	for _, segment := range e.Segments {
		total += segment.UncompressedSize
	}
	return total
}

func (e Entry) CompressedSize() uint64 {
	var total uint64
	for _, segment := range e.Segments {
		total += segment.CompressedSize
	}
	return total
}

func readIndex(rs io.ReadSeeker) ([]byte, error) {
	var offset uint64
	if err := binary.Read(rs, binary.LittleEndian, &offset); err != nil {
		return nil, fmt.Errorf("read index offset: %w", err)
	}
	if offset == 0 {
		return nil, ErrMissingIndexOffset
	}
	if _, err := rs.Seek(int64(offset), io.SeekStart); err != nil {
		return nil, fmt.Errorf("seek index: %w", err)
	}

	flag, err := readByte(rs)
	if err != nil {
		return nil, fmt.Errorf("read index flag: %w", err)
	}
	if flag == indexContinue {
		if _, err := rs.Seek(8, io.SeekCurrent); err != nil {
			return nil, fmt.Errorf("seek continued index padding: %w", err)
		}
		if err := binary.Read(rs, binary.LittleEndian, &offset); err != nil {
			return nil, fmt.Errorf("read continued index offset: %w", err)
		}
		if _, err := rs.Seek(int64(offset), io.SeekStart); err != nil {
			return nil, fmt.Errorf("seek continued index: %w", err)
		}
		flag, err = readByte(rs)
		if err != nil {
			return nil, fmt.Errorf("read continued index flag: %w", err)
		}
	}

	switch flag {
	case indexCompressed:
		var compressedSize, uncompressedSize uint64
		if err := binary.Read(rs, binary.LittleEndian, &compressedSize); err != nil {
			return nil, fmt.Errorf("read compressed index size: %w", err)
		}
		if err := binary.Read(rs, binary.LittleEndian, &uncompressedSize); err != nil {
			return nil, fmt.Errorf("read uncompressed index size: %w", err)
		}
		compressed := make([]byte, compressedSize)
		if _, err := io.ReadFull(rs, compressed); err != nil {
			return nil, fmt.Errorf("read compressed index: %w", err)
		}
		zr, err := zlib.NewReader(bytes.NewReader(compressed))
		if err != nil {
			return nil, fmt.Errorf("open compressed index: %w", err)
		}
		defer zr.Close()
		index, err := io.ReadAll(zr)
		if err != nil {
			return nil, fmt.Errorf("decompress index: %w", err)
		}
		if uint64(len(index)) != uncompressedSize {
			return nil, fmt.Errorf("index size mismatch: got %d want %d", len(index), uncompressedSize)
		}
		return index, nil
	case indexUncompressed:
		var size uint64
		if err := binary.Read(rs, binary.LittleEndian, &size); err != nil {
			return nil, fmt.Errorf("read uncompressed index size: %w", err)
		}
		index := make([]byte, size)
		if _, err := io.ReadFull(rs, index); err != nil {
			return nil, fmt.Errorf("read uncompressed index: %w", err)
		}
		return index, nil
	default:
		return nil, fmt.Errorf("%w: 0x%02x", ErrUnexpectedIndexFlag, flag)
	}
}

func parseEntries(index []byte) ([]Entry, error) {
	reader := bytes.NewReader(index)
	entries := make([]Entry, 0)
	for reader.Len() > 0 {
		entry, err := readEntry(reader)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func readEntry(r *bytes.Reader) (Entry, error) {
	var entry Entry
	name, err := readName(r)
	if err != nil {
		return entry, fmt.Errorf("read entry chunk name: %w", err)
	}
	if string(name[:]) != "File" {
		encryption, err := readEncryption(r, name)
		if err != nil {
			return entry, err
		}
		entry.Encryption = &encryption
		name, err = readName(r)
		if err != nil {
			return entry, fmt.Errorf("read file chunk name: %w", err)
		}
		if string(name[:]) != "File" {
			return entry, fmt.Errorf("%w: missing File chunk", ErrInvalidArchive)
		}
	}

	var fileSize uint64
	if err := binary.Read(r, binary.LittleEndian, &fileSize); err != nil {
		return entry, fmt.Errorf("read File chunk size: %w", err)
	}
	if fileSize > uint64(r.Len()) {
		return entry, fmt.Errorf("%w: File chunk exceeds index length", ErrInvalidArchive)
	}
	chunkEnd := int64(r.Size()) - int64(r.Len()) + int64(fileSize)

	for currentOffset(r) < chunkEnd {
		chunkName, err := readName(r)
		if err != nil {
			return entry, fmt.Errorf("read inner chunk name: %w", err)
		}
		switch string(chunkName[:]) {
		case "time":
			t, err := readTime(r)
			if err != nil {
				return entry, err
			}
			entry.Time = t
		case "adlr":
			adlr, err := readAdler(r)
			if err != nil {
				return entry, err
			}
			entry.Adler = adlr
		case "segm":
			segments, err := readSegments(r)
			if err != nil {
				return entry, err
			}
			entry.Segments = segments
		case "info":
			info, err := readInfo(r)
			if err != nil {
				return entry, err
			}
			entry.Info = info
		default:
			if err := skipSizedChunk(r); err != nil {
				return entry, fmt.Errorf("skip unknown chunk %q: %w", string(chunkName[:]), err)
			}
		}
	}

	if len(entry.Segments) == 0 || entry.Info.FilePath == "" {
		return entry, fmt.Errorf("%w: incomplete File chunk", ErrInvalidArchive)
	}
	if entry.Encryption != nil && entry.Encryption.Adler32 != entry.Adler.Value {
		return entry, fmt.Errorf("%w: encrypted checksum does not match adlr chunk", ErrInvalidArchive)
	}
	return entry, nil
}

func readEncryption(r *bytes.Reader, name [4]byte) (Encryption, error) {
	var size uint64
	var checksum uint32
	var pathLength uint16
	if err := binary.Read(r, binary.LittleEndian, &size); err != nil {
		return Encryption{}, fmt.Errorf("read encryption size: %w", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &checksum); err != nil {
		return Encryption{}, fmt.Errorf("read encryption checksum: %w", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &pathLength); err != nil {
		return Encryption{}, fmt.Errorf("read encryption path length: %w", err)
	}
	pathBytesLen, hasTerminator, err := sizedUTF16PathBytes(size, 4+2, pathLength)
	if err != nil {
		return Encryption{}, fmt.Errorf("%w: invalid encryption chunk size", ErrInvalidArchive)
	}
	pathBytes := make([]byte, pathBytesLen)
	if _, err := io.ReadFull(r, pathBytes); err != nil {
		return Encryption{}, fmt.Errorf("read encryption path: %w", err)
	}
	if hasTerminator {
		if _, err := r.Seek(2, io.SeekCurrent); err != nil {
			return Encryption{}, fmt.Errorf("skip encryption path terminator: %w", err)
		}
	}
	return Encryption{ChunkName: name, Adler32: checksum, FilePath: stringFromUTF16LE(pathBytes), PathTerminated: hasTerminator}, nil
}

func readTime(r *bytes.Reader) (FileTime, error) {
	var size uint64
	var timestamp uint64
	if err := binary.Read(r, binary.LittleEndian, &size); err != nil {
		return FileTime{}, fmt.Errorf("read time size: %w", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &timestamp); err != nil {
		return FileTime{}, fmt.Errorf("read timestamp: %w", err)
	}
	if size != 8 {
		return FileTime{}, fmt.Errorf("%w: invalid time chunk size", ErrInvalidArchive)
	}
	return FileTime{TimestampMillis: timestamp}, nil
}

func readAdler(r *bytes.Reader) (Adler, error) {
	var size uint64
	var checksum uint32
	if err := binary.Read(r, binary.LittleEndian, &size); err != nil {
		return Adler{}, fmt.Errorf("read adler size: %w", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &checksum); err != nil {
		return Adler{}, fmt.Errorf("read adler checksum: %w", err)
	}
	if size != 4 {
		return Adler{}, fmt.Errorf("%w: invalid adler chunk size", ErrInvalidArchive)
	}
	return Adler{Value: checksum}, nil
}

func readSegments(r *bytes.Reader) ([]Segment, error) {
	var size uint64
	if err := binary.Read(r, binary.LittleEndian, &size); err != nil {
		return nil, fmt.Errorf("read segment size: %w", err)
	}
	if size%28 != 0 {
		return nil, fmt.Errorf("%w: invalid segment chunk size", ErrInvalidArchive)
	}
	segments := make([]Segment, 0, size/28)
	for i := uint64(0); i < size/28; i++ {
		compressed, err := readByte(r)
		if err != nil {
			return nil, fmt.Errorf("read segment compression flag: %w", err)
		}
		if _, err := r.Seek(3, io.SeekCurrent); err != nil {
			return nil, fmt.Errorf("skip segment padding: %w", err)
		}
		var segment Segment
		segment.IsCompressed = compressed != 0
		if err := binary.Read(r, binary.LittleEndian, &segment.Offset); err != nil {
			return nil, fmt.Errorf("read segment offset: %w", err)
		}
		if err := binary.Read(r, binary.LittleEndian, &segment.UncompressedSize); err != nil {
			return nil, fmt.Errorf("read segment uncompressed size: %w", err)
		}
		if err := binary.Read(r, binary.LittleEndian, &segment.CompressedSize); err != nil {
			return nil, fmt.Errorf("read segment compressed size: %w", err)
		}
		segments = append(segments, segment)
	}
	return segments, nil
}

func readInfo(r *bytes.Reader) (Info, error) {
	var size uint64
	var flags uint32
	var uncompressedSize, compressedSize uint64
	var pathLength uint16
	if err := binary.Read(r, binary.LittleEndian, &size); err != nil {
		return Info{}, fmt.Errorf("read info size: %w", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &flags); err != nil {
		return Info{}, fmt.Errorf("read info flags: %w", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &uncompressedSize); err != nil {
		return Info{}, fmt.Errorf("read info uncompressed size: %w", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &compressedSize); err != nil {
		return Info{}, fmt.Errorf("read info compressed size: %w", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &pathLength); err != nil {
		return Info{}, fmt.Errorf("read info path length: %w", err)
	}
	pathBytesLen, hasTerminator, err := sizedUTF16PathBytes(size, 4+8+8+2, pathLength)
	if err != nil {
		return Info{}, fmt.Errorf("%w: invalid info chunk size", ErrInvalidArchive)
	}
	pathBytes := make([]byte, pathBytesLen)
	if _, err := io.ReadFull(r, pathBytes); err != nil {
		return Info{}, fmt.Errorf("read info path: %w", err)
	}
	if hasTerminator {
		if _, err := r.Seek(2, io.SeekCurrent); err != nil {
			return Info{}, fmt.Errorf("skip info path terminator: %w", err)
		}
	}
	return Info{
		IsEncrypted:      flags&fileIsEncrypted != 0,
		UncompressedSize: uncompressedSize,
		CompressedSize:   compressedSize,
		FilePath:         stringFromUTF16LE(pathBytes),
		PathTerminated:   hasTerminator,
	}, nil
}

func sizedUTF16PathBytes(chunkSize uint64, fixedSize uint64, pathLength uint16) (int, bool, error) {
	expectedPathBytes := uint64(pathLength) * 2
	if chunkSize == fixedSize+expectedPathBytes {
		return int(expectedPathBytes), false, nil
	}
	if chunkSize == fixedSize+expectedPathBytes+2 {
		return int(expectedPathBytes), true, nil
	}
	if chunkSize < fixedSize || (chunkSize-fixedSize)%2 != 0 {
		return 0, false, fmt.Errorf("chunk size %d cannot contain UTF-16 path length %d", chunkSize, pathLength)
	}
	return 0, false, fmt.Errorf("chunk size %d does not match UTF-16 path length %d", chunkSize, pathLength)
}

type encodeOptions struct {
	OmitPathTerminators bool
}

func encodeIndex(entries []Entry, opts encodeOptions) ([]byte, error) {
	var uncompressed bytes.Buffer
	for _, entry := range entries {
		if err := writeEntry(&uncompressed, entry, opts); err != nil {
			return nil, err
		}
	}

	var compressed bytes.Buffer
	zw, err := zlib.NewWriterLevel(&compressed, zlib.BestCompression)
	if err != nil {
		return nil, err
	}
	if _, err := zw.Write(uncompressed.Bytes()); err != nil {
		zw.Close()
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}

	if compressed.Len()+1+8+8 < uncompressed.Len()+1+8 {
		var out bytes.Buffer
		out.WriteByte(indexCompressed)
		writeUint64(&out, uint64(compressed.Len()))
		writeUint64(&out, uint64(uncompressed.Len()))
		out.Write(compressed.Bytes())
		return out.Bytes(), nil
	}

	var out bytes.Buffer
	out.WriteByte(indexUncompressed)
	writeUint64(&out, uint64(uncompressed.Len()))
	out.Write(uncompressed.Bytes())
	return out.Bytes(), nil
}

func writeEntry(w io.Writer, entry Entry, opts encodeOptions) error {
	if entry.Encryption != nil {
		if err := writeEncryption(w, *entry.Encryption, opts); err != nil {
			return err
		}
	}

	var body bytes.Buffer
	writeTime(&body, entry.Time)
	writeAdler(&body, entry.Adler)
	writeSegments(&body, entry.Segments)
	writeInfo(&body, entry.Info, opts)

	if _, err := w.Write([]byte("File")); err != nil {
		return err
	}
	writeUint64(w, uint64(body.Len()))
	_, err := w.Write(body.Bytes())
	return err
}

func writeEncryption(w io.Writer, encryption Encryption, opts encodeOptions) error {
	if _, err := w.Write(encryption.ChunkName[:]); err != nil {
		return err
	}
	pathBytes := utf16LEBytes(encryption.FilePath)
	terminatorSize := pathTerminatorSize(opts)
	writeUint64(w, uint64(4+2+len(pathBytes)+terminatorSize))
	writeUint32(w, encryption.Adler32)
	writeUint16(w, uint16(len([]rune(encryption.FilePath))))
	if _, err := w.Write(pathBytes); err != nil {
		return err
	}
	if terminatorSize == 0 {
		return nil
	}
	_, err := w.Write([]byte{0, 0})
	return err
}

func writeTime(w io.Writer, t FileTime) {
	w.Write([]byte("time"))
	writeUint64(w, 8)
	writeUint64(w, t.TimestampMillis)
}

func writeAdler(w io.Writer, adlr Adler) {
	w.Write([]byte("adlr"))
	writeUint64(w, 4)
	writeUint32(w, adlr.Value)
}

func writeSegments(w io.Writer, segments []Segment) {
	w.Write([]byte("segm"))
	writeUint64(w, uint64(len(segments)*28))
	for _, segment := range segments {
		if segment.IsCompressed {
			w.Write([]byte{1, 0, 0, 0})
		} else {
			w.Write([]byte{0, 0, 0, 0})
		}
		writeUint64(w, segment.Offset)
		writeUint64(w, segment.UncompressedSize)
		writeUint64(w, segment.CompressedSize)
	}
}

func writeInfo(w io.Writer, info Info, opts encodeOptions) {
	w.Write([]byte("info"))
	pathBytes := utf16LEBytes(info.FilePath)
	terminatorSize := pathTerminatorSize(opts)
	writeUint64(w, uint64(4+8+8+2+len(pathBytes)+terminatorSize))
	if info.IsEncrypted {
		writeUint32(w, fileIsEncrypted)
	} else {
		writeUint32(w, 0)
	}
	writeUint64(w, info.UncompressedSize)
	writeUint64(w, info.CompressedSize)
	writeUint16(w, uint16(len([]rune(info.FilePath))))
	w.Write(pathBytes)
	if terminatorSize != 0 {
		w.Write([]byte{0, 0})
	}
}

func pathTerminatorSize(opts encodeOptions) int {
	if opts.OmitPathTerminators {
		return 0
	}
	return 2
}

func makeEntry(internalPath string, data []byte, offset uint64, encryptionType string, timestampMillis uint64) (Entry, []byte, error) {
	checksum := adler32.Checksum(data)
	payload := append([]byte(nil), data...)

	var encryption *Encryption
	infoPath := internalPath
	isEncrypted := encryptionType != "" && encryptionType != EncryptionNone
	if isEncrypted {
		params, ok := encryptionParametersByType[encryptionType]
		if !ok {
			return Entry{}, nil, fmt.Errorf("%w: %s", ErrUnsupportedEncryption, encryptionType)
		}
		encrypted, err := xorData(payload, checksum, encryptionType)
		if err != nil {
			return Entry{}, nil, err
		}
		payload = encrypted
		encryption = &Encryption{
			ChunkName:      params.chunkName,
			Adler32:        checksum,
			FilePath:       internalPath,
			PathTerminated: true,
		}
		infoPath = encryptedPathHash(internalPath)
	}

	uncompressedSize := uint64(len(payload))
	compressed, err := compressBest(payload)
	if err != nil {
		return Entry{}, nil, err
	}

	isCompressed := len(compressed) < len(payload)
	output := payload
	if isCompressed {
		output = compressed
	}
	compressedSize := uint64(len(output))

	entry := Entry{
		Encryption: encryption,
		Time:       FileTime{TimestampMillis: timestampMillis},
		Adler:      Adler{Value: checksum},
		Segments: []Segment{{
			IsCompressed:     isCompressed,
			Offset:           offset,
			UncompressedSize: uncompressedSize,
			CompressedSize:   compressedSize,
		}},
		Info: Info{
			IsEncrypted:      isEncrypted,
			UncompressedSize: uncompressedSize,
			CompressedSize:   compressedSize,
			FilePath:         infoPath,
			PathTerminated:   true,
		},
	}
	return entry, output, nil
}

func compressBest(data []byte) ([]byte, error) {
	var out bytes.Buffer
	zw, err := zlib.NewWriterLevel(&out, zlib.BestCompression)
	if err != nil {
		return nil, err
	}
	if _, err := zw.Write(data); err != nil {
		zw.Close()
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func decompress(data []byte) ([]byte, error) {
	zr, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	return io.ReadAll(zr)
}

func readName(r *bytes.Reader) ([4]byte, error) {
	var name [4]byte
	_, err := io.ReadFull(r, name[:])
	return name, err
}

func readByte(r io.Reader) (byte, error) {
	var b [1]byte
	_, err := io.ReadFull(r, b[:])
	return b[0], err
}

func skipSizedChunk(r *bytes.Reader) error {
	var size uint64
	if err := binary.Read(r, binary.LittleEndian, &size); err != nil {
		return err
	}
	if size > uint64(r.Len()) {
		return io.ErrUnexpectedEOF
	}
	_, err := r.Seek(int64(size), io.SeekCurrent)
	return err
}

func currentOffset(r *bytes.Reader) int64 {
	return int64(r.Size()) - int64(r.Len())
}

func writeUint16(w io.Writer, v uint16) {
	_ = binary.Write(w, binary.LittleEndian, v)
}

func writeUint32(w io.Writer, v uint32) {
	_ = binary.Write(w, binary.LittleEndian, v)
}

func writeUint64(w io.Writer, v uint64) {
	_ = binary.Write(w, binary.LittleEndian, v)
}
