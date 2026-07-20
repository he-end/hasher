package hasher

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
)

// hash returns the SHA-256 hex string for the input string.
func (s *sha256Conf) hash(data string) string {
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}

// hashBytes returns the SHA-256 hex string for the input []byte.
func (s *sha256Conf) hashBytes(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// verify compares data against a stored SHA-256 hex hash.
func (s *sha256Conf) verify(data, hashed string) bool {
	return s.hash(data) == hashed
}

// hash returns the SHA-512 hex string for the input string.
func (s *sha512Conf) hash(data string) string {
	h := sha512.Sum512([]byte(data))
	return hex.EncodeToString(h[:])
}

// hashBytes returns the SHA-512 hex string for the input []byte.
func (s *sha512Conf) hashBytes(data []byte) string {
	h := sha512.Sum512(data)
	return hex.EncodeToString(h[:])
}

// verify compares data against a stored SHA-512 hex hash.
func (s *sha512Conf) verify(data, hashed string) bool {
	return s.hash(data) == hashed
}

// Hash returns a hex string of the data using the configured algorithm.
//
// Output: 64-char hex string (sha256) or 128-char hex string (sha512).
// No salt is used — suitable only for integrity checks, not passwords.
func (f *fastHash) Hash(data string) string {
	switch f.hasher {
	case "sha256":
		return f.sha256.hash(data)
	case "sha512":
		return f.sha512.hash(data)
	}
	return ""
}

// HashBytes returns a hex string from []byte using the configured algorithm.
func (f *fastHash) HashBytes(data []byte) string {
	switch f.hasher {
	case "sha256":
		return f.sha256.hashBytes(data)
	case "sha512":
		return f.sha512.hashBytes(data)
	}
	return ""
}

// VerifyHash compares data against a stored hex hash.
//
// Returns true if hash(data) == hashed, false otherwise.
func (f *fastHash) VerifyHash(data, hashed string) bool {
	switch f.hasher {
	case "sha256":
		return f.sha256.verify(data, hashed)
	case "sha512":
		return f.sha512.verify(data, hashed)
	}
	return false
}
