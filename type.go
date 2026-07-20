// Package hasher provides password hashing (argon2id, bcrypt, scrypt, pbkdf2)
// and fast hashing (sha256, sha512) with both default and custom configurations.
//
// # 1. Password Hashing — default config (pick one algorithm)
//
//	ph, err := hasher.NewPasswordHashingConfDefault("argon2")
//	hashed, _ := ph.Hash("secret123")
//	ok, _ := ph.Verify("secret123", hashed) // true
//
// # 2. Password Hashing — manual config (pick one algorithm)
//
//	ph, err := hasher.NewPasswordHashingManual(hasher.PasswordHashingConfig{
//	    Hasher: "bcrypt",
//	    Bcrypt: &hasher.BcryptConfig{Cost: 12},
//	})
//	hashed, _ := ph.Hash("secret123")
//	ok, _ := ph.Verify("secret123", hashed)
//
// # 3. Fast Hashing — default config (pick one algorithm)
//
//	fh, err := hasher.NewFastHashingConfDefault("sha256")
//	h := fh.Hash("hello")
//	ok := fh.VerifyHash("hello", h) // true
//
// # 4. Fast Hashing — manual config
//
//	fh, err := hasher.NewFastHashingManual(hasher.FastHashingConfig{
//	    Hasher: "sha512",
//	})
//	h := fh.Hash("hello")
//
// Password hash output format:
//   - argon2/scrypt/pbkdf2: "algo$base64_salt$base64_hash"
//   - bcrypt: native "$2a$..." format (no separate salt)
//
// Note: bcrypt truncates passwords exceeding 72 bytes (standard bcrypt behavior).
package hasher

// PasswordHashing is the interface for password hashing
// with automatic salt and verification against stored hashes.
//
// Implementations: argon2id (default), bcrypt, scrypt, pbkdf2.
type PasswordHashing interface {
	// Hash produces a hash from password with a random salt.
	// Output format: "algo$salt$hash" (except bcrypt: native format).
	Hash(password string) (string, error)

	// Verify compares a password against a stored hash.
	// Automatically detects the algorithm from the hash prefix.
	// Returns true if match, false if mismatch, error if invalid format.
	Verify(password, hashed string) (bool, error)
}

// pwdHash stores configurations for all password hashing algorithms
// and dispatches to the selected algorithm via the hasher field.
type pwdHash struct {
	hasher string       // active algorithm: "argon2", "bcrypt", "scrypt", "pbkdf2"
	argon2 *argon2Conf  // argon2id configuration
	bcrypt *bcryptConf  // bcrypt configuration
	scrypt *scryptConf  // scrypt configuration
	pbkdf2 *pbkdf2Conf  // pbkdf2 configuration
}

// argon2Conf holds parameters for Argon2id.
//
// OWASP recommendations (as of 2023):
//
//	time=2, memory=64*1024 (64MB), threads=1, keyLen=32
//
// This library defaults to time=1 for speed.
type argon2Conf struct {
	time     uint32 // number of iterations (passes), higher = slower
	memory   uint32 // memory in KiB, higher = more resistant to GPU attacks
	threads  uint8  // number of parallel threads
	keyLen   uint32 // output hash length in bytes
	saltLen  int    // salt length in bytes
	separate string // output delimiter (default "$")
}

// bcryptConf holds parameters for bcrypt.
//
// Cost determines the complexity (4–31). Default is 10 (~100ms per hash).
// bcrypt has a 72-byte limit on password length.
type bcryptConf struct {
	cost     int    // bcrypt cost factor (4–31)
	separate string // unused (bcrypt uses its own native format)
}

// scryptConf holds parameters for scrypt.
//
// scrypt is designed to resist hardware attacks (ASIC/FPGA).
// N is the CPU/memory factor (must be a power of 2). Default N=32768.
type scryptConf struct {
	N        int    // CPU/memory factor (must be power of 2, e.g. 32768)
	R        int    // block parameter (default 8)
	P        int    // parallel parameter (default 1)
	keyLen   int    // output hash length in bytes
	saltLen  int    // salt length in bytes
	separate string // output delimiter (default "$")
}

// pbkdf2Conf holds parameters for PBKDF2-HMAC-SHA256.
//
// PBKDF2 is a NIST standard, widely used in enterprise environments.
// Default: 600,000 iterations (OWASP 2023 recommendation for HMAC-SHA256).
type pbkdf2Conf struct {
	iter     int    // iteration count (default 600000)
	keyLen   int    // output hash length in bytes
	saltLen  int    // salt length in bytes
	separate string // output delimiter (default "$")
}

// PasswordHashingConfig is the manual configuration for selecting
// a single password hashing algorithm with its parameters.
//
// Example:
//
//	hasher.NewPasswordHashingManual(hasher.PasswordHashingConfig{
//	    Hasher: "bcrypt",
//	    Bcrypt: &hasher.BcryptConfig{Cost: 12},
//	})
type PasswordHashingConfig struct {
	Hasher string         // required: "argon2", "bcrypt", "scrypt", "pbkdf2"
	Argon2 *Argon2Config  // set if Hasher="argon2"
	Bcrypt *BcryptConfig  // set if Hasher="bcrypt"
	Scrypt *ScryptConfig  // set if Hasher="scrypt"
	PBKDF2 *PBKDF2Config  // set if Hasher="pbkdf2"
}

// Argon2Config is the public configuration for argon2id.
type Argon2Config struct {
	Time     uint32 // number of iterations (default 1)
	Memory   uint32 // memory in KiB (default 64*1024 = 64MB)
	Threads  uint8  // number of parallel threads (default 4)
	KeyLen   uint32 // hash length in bytes (default 32)
	SaltLen  int    // salt length in bytes (default 16)
	Separate string // output delimiter, leave empty for default "$"
}

// BcryptConfig is the public configuration for bcrypt.
// Cost of 0 will automatically become DefaultCost (10).
type BcryptConfig struct {
	Cost     int    // cost factor 4–31, 0=default(10)
	Separate string // unused
}

// ScryptConfig is the public configuration for scrypt.
type ScryptConfig struct {
	N        int    // CPU/memory factor, must be a power of 2
	R        int    // block parameter
	P        int    // parallel parameter
	KeyLen   int    // hash length in bytes
	SaltLen  int    // salt length in bytes
	Separate string // output delimiter, leave empty for default "$"
}

// PBKDF2Config is the public configuration for PBKDF2-HMAC-SHA256.
type PBKDF2Config struct {
	Iter     int    // iteration count
	KeyLen   int    // hash length in bytes
	SaltLen  int    // salt length in bytes
	Separate string // output delimiter, leave empty for default "$"
}

// FastHashing is the interface for fast, saltless hashing
// (sha256, sha512) with string verification.
//
// Suitable for integrity checks, fingerprints, and checksums — not passwords.
type FastHashing interface {
	// Hash returns a hex string of the data.
	Hash(data string) string

	// HashBytes returns a hex string from []byte.
	HashBytes(data []byte) string

	// VerifyHash compares data against a stored hex hash.
	VerifyHash(data string, hashed string) bool
}

// fastHash stores fast hashing configurations and dispatches
// to the selected algorithm via the hasher field.
type fastHash struct {
	hasher string
	sha256 *sha256Conf
	sha512 *sha512Conf
}

// sha256Conf is the configuration for SHA-256.
// No additional parameters.
type sha256Conf struct{}

// sha512Conf is the configuration for SHA-512.
// No additional parameters.
type sha512Conf struct{}

// FastHashingConfig is the manual configuration for selecting
// a single fast hashing algorithm.
//
// Example:
//
//	hasher.NewFastHashingManual(hasher.FastHashingConfig{
//	    Hasher: "sha512",
//	})
type FastHashingConfig struct {
	Hasher string         // required: "sha256" or "sha512"
	SHA256 *SHA256Config  // set if Hasher="sha256" (optional, empty ok)
	SHA512 *SHA512Config  // set if Hasher="sha512" (optional, empty ok)
}

// SHA256Config is the public configuration for SHA-256.
// No additional parameters.
type SHA256Config struct{}

// SHA512Config is the public configuration for SHA-512.
// No additional parameters.
type SHA512Config struct{}
