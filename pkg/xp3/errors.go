package xp3

import "errors"

var (
	ErrInvalidArchive        = errors.New("invalid xp3 archive")
	ErrMissingIndexOffset    = errors.New("xp3 index offset is missing")
	ErrUnexpectedIndexFlag   = errors.New("unexpected xp3 index flag")
	ErrUnsupportedEncryption = errors.New("unsupported encryption type")
	ErrEncryptedFile         = errors.New("file is encrypted and no encryption type was specified")
	ErrDuplicateFile         = errors.New("duplicate file path in archive")
	ErrArchivePacked         = errors.New("archive is already packed")
	ErrChecksumMismatch      = errors.New("checksum mismatch")
	ErrUnsafePath            = errors.New("unsafe archive path")
)
