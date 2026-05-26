package xp3

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"io"
)

var scrambledTextMagic = []byte{0xFE, 0xFE}
var scrambledTextBOM = []byte{0xFF, 0xFE}

// DescrambleKirikiriText decodes Kirikiri scrambled UTF-16 text payloads.
// It returns ok=false when data does not have a recognized scrambled-text header.
func DescrambleKirikiriText(data []byte) ([]byte, bool, error) {
	if len(data) < 5 || !bytes.Equal(data[:2], scrambledTextMagic) || !bytes.Equal(data[3:5], scrambledTextBOM) {
		return nil, false, nil
	}

	var utf16Data []byte
	var err error
	switch mode := data[2]; mode {
	case 0:
		utf16Data, err = descrambleMode0(data[5:])
	case 1:
		utf16Data, err = descrambleMode1(data[5:])
	case 2:
		utf16Data, err = decompressScrambledText(data[5:])
	default:
		return nil, true, fmt.Errorf("unsupported scrambling mode %d", mode)
	}
	if err != nil {
		return nil, true, err
	}
	return []byte(stringFromUTF16LE(utf16Data)), true, nil
}

func descrambleMode0(data []byte) ([]byte, error) {
	if len(data)%2 != 0 {
		return nil, fmt.Errorf("%w: scrambled UTF-16 payload has odd length", ErrInvalidArchive)
	}
	out := append([]byte(nil), data...)
	for i := 0; i < len(out); i += 2 {
		if out[i+1] == 0 && out[i] < 0x20 {
			continue
		}
		out[i+1] ^= out[i] & 0xFE
		out[i] ^= 1
	}
	return out, nil
}

func descrambleMode1(data []byte) ([]byte, error) {
	if len(data)%2 != 0 {
		return nil, fmt.Errorf("%w: scrambled UTF-16 payload has odd length", ErrInvalidArchive)
	}
	out := append([]byte(nil), data...)
	for i := 0; i < len(out); i += 2 {
		c := binary.LittleEndian.Uint16(out[i : i+2])
		c = ((c & 0xAAAA) >> 1) | ((c & 0x5555) << 1)
		binary.LittleEndian.PutUint16(out[i:i+2], c)
	}
	return out, nil
}

func decompressScrambledText(data []byte) ([]byte, error) {
	if len(data) < 16 {
		return nil, fmt.Errorf("%w: compressed scrambled text header is truncated", ErrInvalidArchive)
	}
	compressedLength := binary.LittleEndian.Uint64(data[:8])
	uncompressedLength := binary.LittleEndian.Uint64(data[8:16])
	compressed := data[16:]
	if compressedLength > uint64(len(compressed)) {
		return nil, fmt.Errorf("%w: compressed scrambled text payload is truncated", ErrInvalidArchive)
	}
	compressed = compressed[:compressedLength]

	zr, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, err
	}
	defer zr.Close()

	out, err := io.ReadAll(zr)
	if err != nil {
		return nil, err
	}
	if uint64(len(out)) != uncompressedLength {
		return nil, fmt.Errorf("%w: scrambled text size got %d want %d", ErrInvalidArchive, len(out), uncompressedLength)
	}
	return out, nil
}
