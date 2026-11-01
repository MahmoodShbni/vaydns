// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package security

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

type EncryptionKeyInfo struct {
	MethodID   int
	MethodName string
	Key        string
	Path       string
	Loaded     bool
	Generated  bool
}

// EnsureServerEncryptionKey loads the encryption key at path, or generates and
// persists one if it is missing or the wrong length. It was decoupled from the
// upstream MasterDnsVPN config type so the transport can be used standalone:
// callers pass the encryption method ID and key file path directly.
func EnsureServerEncryptionKey(method int, path string) (EncryptionKeyInfo, error) {
	info := EncryptionKeyInfo{
		MethodID:   method,
		MethodName: EncryptionMethodName(method),
		Path:       path,
	}

	requiredLength := requiredKeyLength(method)
	raw, err := os.ReadFile(info.Path)
	if err == nil {
		key := strings.TrimSpace(string(raw))
		if len(key) == requiredLength {
			info.Key = key
			info.Loaded = true
			return info, nil
		}
	}

	key, err := generateHexText(requiredLength)
	if err != nil {
		return info, fmt.Errorf("generate encryption key: %w", err)
	}
	if err := os.WriteFile(info.Path, []byte(key), 0o600); err != nil {
		return info, fmt.Errorf("write encryption key file %s: %w", info.Path, err)
	}

	info.Key = key
	info.Generated = true
	return info, nil
}

func EncryptionMethodName(methodID int) string {
	switch methodID {
	case 0:
		return "NONE"
	case 1:
		return "XOR"
	case 2:
		return "ChaCha20"
	case 3:
		return "AES-128-GCM"
	case 4:
		return "AES-192-GCM"
	case 5:
		return "AES-256-GCM"
	default:
		return "UNKNOWN"
	}
}

func requiredKeyLength(methodID int) int {
	switch methodID {
	case 3:
		return 16
	case 4:
		return 24
	default:
		return 32
	}
}

func generateHexText(length int) (string, error) {
	if length <= 0 {
		return "", nil
	}
	buf := make([]byte, (length+1)/2)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf)[:length], nil
}
