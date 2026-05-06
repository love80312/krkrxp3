package xp3

import "fmt"

type Extractability struct {
	Extractable bool
	Protected   bool
	Encrypted   bool

	ProtectedPaths []string
	EncryptedPaths []string
	UnsafePaths    []string
}

func CanExtract(path string, encryptionType string) (Extractability, error) {
	reader, err := OpenReader(path)
	if err != nil {
		return Extractability{}, err
	}
	defer reader.Close()

	return reader.Extractability(encryptionType)
}

func (r *Reader) Extractability(encryptionType string) (Extractability, error) {
	if encryptionType == "" {
		encryptionType = EncryptionNone
	}
	if !IsEncryptionType(encryptionType) {
		return Extractability{}, fmt.Errorf("%w: %s", ErrUnsupportedEncryption, encryptionType)
	}

	check := Extractability{Extractable: true}
	for _, entry := range r.entries {
		path := entry.FilePath()
		if isProtectedArchiveMarker(path) {
			check.Protected = true
			check.ProtectedPaths = append(check.ProtectedPaths, path)
			continue
		}
		if _, err := normalizeArchivePath(path); err != nil {
			check.UnsafePaths = append(check.UnsafePaths, path)
			continue
		}
		if entry.IsEncrypted() && encryptionType == EncryptionNone {
			check.Encrypted = true
			check.EncryptedPaths = append(check.EncryptedPaths, path)
		}
	}
	check.Extractable = !check.Protected && !check.Encrypted && len(check.UnsafePaths) == 0
	return check, nil
}
