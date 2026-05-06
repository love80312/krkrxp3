package xp3

import (
	"crypto/md5"
	"encoding/hex"
	"sort"
	"strings"
	"unicode/utf16"
)

const EncryptionNone = "none"

type encryptionParameters struct {
	masterKey    uint32
	secondaryKey byte
	xorFirstByte bool
	chunkName    [4]byte
}

type EncryptionProbeResult struct {
	Type         string
	Matched      bool
	FailedPath   string
	GotChecksum  uint32
	WantChecksum uint32
	Err          error
}

var encryptionParametersByType = map[string]encryptionParameters{
	EncryptionNone:    {masterKey: 0x00000000, secondaryKey: 0x00, xorFirstByte: false, chunkName: [4]byte{'e', 'l', 'i', 'F'}},
	"neko_vol1":       {masterKey: 0x1548E29C, secondaryKey: 0xD7, xorFirstByte: false, chunkName: [4]byte{'e', 'l', 'i', 'F'}},
	"neko_vol1_steam": {masterKey: 0x44528B87, secondaryKey: 0x23, xorFirstByte: false, chunkName: [4]byte{'e', 'l', 'i', 'F'}},
	"neko_vol0":       {masterKey: 0x1548E29C, secondaryKey: 0xD7, xorFirstByte: true, chunkName: [4]byte{'n', 'e', 'k', 'o'}},
	"neko_vol0_steam": {masterKey: 0x44528B87, secondaryKey: 0x23, xorFirstByte: true, chunkName: [4]byte{'n', 'e', 'k', 'o'}},
}

func EncryptionTypes() []string {
	types := make([]string, 0, len(encryptionParametersByType))
	for encryptionType := range encryptionParametersByType {
		types = append(types, encryptionType)
	}
	sort.Strings(types)
	return types
}

func IsEncryptionType(encryptionType string) bool {
	_, ok := encryptionParametersByType[encryptionType]
	return ok
}

func xorData(data []byte, adler32 uint32, encryptionType string) ([]byte, error) {
	params, ok := encryptionParametersByType[encryptionType]
	if !ok {
		return nil, ErrUnsupportedEncryption
	}

	out := append([]byte(nil), data...)
	if len(out) == 0 {
		return out, nil
	}

	adlerKey := adler32 ^ params.masterKey
	xorKey := byte((adlerKey>>24 ^ adlerKey>>16 ^ adlerKey>>8 ^ adlerKey) & 0xFF)
	if xorKey == 0 {
		xorKey = params.secondaryKey
	}

	if params.xorFirstByte {
		firstByteKey := byte(adlerKey & 0xFF)
		if firstByteKey == 0 {
			firstByteKey = byte(params.masterKey & 0xFF)
		}
		out[0] ^= firstByteKey
	}

	for i := range out {
		out[i] ^= xorKey
	}

	return out, nil
}

func encryptedPathHash(path string) string {
	sum := md5.Sum(utf16LEBytes(strings.ToLower(path)))
	return hex.EncodeToString(sum[:])
}

func utf16LEBytes(s string) []byte {
	encoded := utf16.Encode([]rune(s))
	out := make([]byte, 0, len(encoded)*2)
	for _, r := range encoded {
		out = append(out, byte(r), byte(r>>8))
	}
	return out
}

func stringFromUTF16LE(data []byte) string {
	if len(data)%2 != 0 {
		data = data[:len(data)-1]
	}
	encoded := make([]uint16, 0, len(data)/2)
	for i := 0; i < len(data); i += 2 {
		encoded = append(encoded, uint16(data[i])|uint16(data[i+1])<<8)
	}
	return string(utf16.Decode(encoded))
}
