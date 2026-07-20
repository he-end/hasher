package hasher

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

// hash generates a random salt and hashes the password with argon2id.
// Returns: algorithm name, base64 salt, base64 hash, error.
func (a *argon2Conf) hash(password string) (string, string, string, error) {
	salt := make([]byte, a.saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", "", "", err
	}
	h := argon2.IDKey([]byte(password), salt, a.time, a.memory, a.threads, a.keyLen)
	return "argon2", base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(h), nil
}

// hash produces a bcrypt hash with the configured cost.
// bcrypt handles salt internally, so salt is returned as empty string.
// Returns: algorithm name, empty string, native bcrypt hash ($2a$...), error.
func (b *bcryptConf) hash(password string) (string, string, string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(password), b.cost)
	if err != nil {
		return "", "", "", err
	}
	return "bcrypt", "", string(h), nil
}

// hash generates a random salt and hashes the password with scrypt.
// scrypt requires large amounts of memory, making it resistant to hardware brute-force.
// Returns: algorithm name, base64 salt, base64 hash, error.
func (s *scryptConf) hash(password string) (string, string, string, error) {
	salt := make([]byte, s.saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", "", "", err
	}
	h, err := scrypt.Key([]byte(password), salt, s.N, s.R, s.P, s.keyLen)
	if err != nil {
		return "", "", "", err
	}
	return "scrypt", base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(h), nil
}

// hash generates a random salt and hashes the password with PBKDF2-HMAC-SHA256.
// Returns: algorithm name, base64 salt, base64 hash, error.
func (p *pbkdf2Conf) hash(password string) (string, string, string, error) {
	salt := make([]byte, p.saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", "", "", err
	}
	h := pbkdf2.Key([]byte(password), salt, p.iter, p.keyLen, sha256.New)
	return "pbkdf2", base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(h), nil
}

// Hash produces a password hash using the configured algorithm.
//
// Output format:
//   - argon2/scrypt/pbkdf2: "algo$base64_salt$base64_hash"
//   - bcrypt: native "$2a$cost$salt_and_hash" format (no extra prefix)
//
// Salt is automatically generated using crypto/rand.
func (p *pwdHash) Hash(password string) (string, error) {
	var algo, saltStr, hashStr string
	var err error
	switch p.hasher {
	case "argon2":
		algo, saltStr, hashStr, err = p.argon2.hash(password)
	case "bcrypt":
		algo, saltStr, hashStr, err = p.bcrypt.hash(password)
	case "scrypt":
		algo, saltStr, hashStr, err = p.scrypt.hash(password)
	case "pbkdf2":
		algo, saltStr, hashStr, err = p.pbkdf2.hash(password)
	default:
		return "", fmt.Errorf("unknown hasher: %s", p.hasher)
	}
	if err != nil {
		return "", err
	}
	// bcrypt has its own format, return directly
	if saltStr == "" {
		return hashStr, nil
	}
	return algo + "$" + saltStr + "$" + hashStr, nil
}

// Verify checks a password against a stored hash.
//
// Automatically detects the algorithm:
//   - Prefix "$2a$", "$2b$", "$2y$" → bcrypt (uses bcrypt.CompareHashAndPassword)
//   - Format "algo$salt$hash" → argon2/scrypt/pbkdf2 (re-hash and compare)
//
// Returns:
//   - true, nil  → password matches
//   - false, nil → password does not match
//   - false, err → invalid hash format
func (p *pwdHash) Verify(password, hashed string) (bool, error) {
	// Detect bcrypt by its native prefix ($2a$, $2b$, $2y$)
	if strings.HasPrefix(hashed, "$2a$") || strings.HasPrefix(hashed, "$2b$") || strings.HasPrefix(hashed, "$2y$") {
		err := bcrypt.CompareHashAndPassword([]byte(hashed), []byte(password))
		if err == nil {
			return true, nil
		}
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return false, nil
		}
		return false, err
	}

	// Parse "algo$salt$hash" format
	parts := strings.SplitN(hashed, "$", 3)
	if len(parts) != 3 {
		return false, errors.New("invalid hash format")
	}
	algo, saltB64, hashB64 := parts[0], parts[1], parts[2]

	salt, err := base64.RawStdEncoding.DecodeString(saltB64)
	if err != nil {
		return false, fmt.Errorf("invalid salt: %w", err)
	}

	// Re-hash the password with the same salt and compare
	switch algo {
	case "argon2":
		rehash := argon2.IDKey([]byte(password), salt, p.argon2.time, p.argon2.memory, p.argon2.threads, p.argon2.keyLen)
		return base64.RawStdEncoding.EncodeToString(rehash) == hashB64, nil
	case "scrypt":
		rehash, err := scrypt.Key([]byte(password), salt, p.scrypt.N, p.scrypt.R, p.scrypt.P, p.scrypt.keyLen)
		if err != nil {
			return false, err
		}
		return base64.RawStdEncoding.EncodeToString(rehash) == hashB64, nil
	case "pbkdf2":
		rehash := pbkdf2.Key([]byte(password), salt, p.pbkdf2.iter, p.pbkdf2.keyLen, sha256.New)
		return base64.RawStdEncoding.EncodeToString(rehash) == hashB64, nil
	default:
		return false, fmt.Errorf("unknown algorithm: %s", algo)
	}
}
