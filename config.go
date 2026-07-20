package hasher

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// NewPasswordHashingConfDefault returns a PasswordHashing with argon2id
// using balanced security and performance parameters as the default.
//
// Defaults per algorithm (stored internally, ready to use):
//
//	argon2:  time=1, memory=64MB, threads=4, keyLen=32, saltLen=16
//	bcrypt:  cost=10
//	scrypt:  N=32768, R=8, P=1, keyLen=32, saltLen=16
//	pbkdf2:  iter=600000, keyLen=32, saltLen=16
//
// Active hasher: "argon2".
func NewPasswordHashingConfDefault() PasswordHashing {
	return &pwdHash{
		hasher: "argon2",
		argon2: &argon2Conf{time: 1, memory: 64 * 1024, threads: 4, keyLen: 32, saltLen: 16, separate: "$"},
		bcrypt: &bcryptConf{cost: 10, separate: "$"},
		scrypt: &scryptConf{N: 32768, R: 8, P: 1, keyLen: 32, saltLen: 16, separate: "$"},
		pbkdf2: &pbkdf2Conf{iter: 600000, keyLen: 32, saltLen: 16, separate: "$"},
	}
}

// NewPasswordHashingManual returns a PasswordHashing with custom configuration
// for a single, selected algorithm.
//
// Hasher field is required: "argon2", "bcrypt", "scrypt", or "pbkdf2".
// Only fill in the config struct matching the chosen Hasher.
//
// Example:
//
//	ph, err := hasher.NewPasswordHashingManual(hasher.PasswordHashingConfig{
//	    Hasher: "bcrypt",
//	    Bcrypt: &hasher.BcryptConfig{Cost: 12},
//	})
//	if err != nil {
//	    // handle error
//	}
//	hashed, _ := ph.Hash("password123")
//	ok, _ := ph.Verify("password123", hashed)
//
// Errors:
//   - Selected algorithm config is nil
//   - bcrypt cost outside MinCost (4) – MaxCost (31) range
//   - Unknown hasher
func NewPasswordHashingManual(cfg PasswordHashingConfig) (PasswordHashing, error) {
	switch cfg.Hasher {
	case "argon2":
		if cfg.Argon2 == nil {
			return nil, errors.New("argon2 config is required")
		}
		c := cfg.Argon2
		sep := c.Separate
		if sep == "" {
			sep = "$"
		}
		return &pwdHash{
			hasher: "argon2",
			argon2: &argon2Conf{
				time:     c.Time,
				memory:   c.Memory,
				threads:  c.Threads,
				keyLen:   c.KeyLen,
				saltLen:  c.SaltLen,
				separate: sep,
			},
		}, nil
	case "bcrypt":
		if cfg.Bcrypt == nil {
			return nil, errors.New("bcrypt config is required")
		}
		cost := cfg.Bcrypt.Cost
		if cost == 0 {
			cost = bcrypt.DefaultCost
		}
		if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
			return nil, fmt.Errorf("bcrypt cost must be between %d and %d", bcrypt.MinCost, bcrypt.MaxCost)
		}
		return &pwdHash{
			hasher: "bcrypt",
			bcrypt: &bcryptConf{cost: cost, separate: cfg.Bcrypt.Separate},
		}, nil
	case "scrypt":
		if cfg.Scrypt == nil {
			return nil, errors.New("scrypt config is required")
		}
		c := cfg.Scrypt
		sep := c.Separate
		if sep == "" {
			sep = "$"
		}
		return &pwdHash{
			hasher: "scrypt",
			scrypt: &scryptConf{
				N:        c.N,
				R:        c.R,
				P:        c.P,
				keyLen:   c.KeyLen,
				saltLen:  c.SaltLen,
				separate: sep,
			},
		}, nil
	case "pbkdf2":
		if cfg.PBKDF2 == nil {
			return nil, errors.New("pbkdf2 config is required")
		}
		c := cfg.PBKDF2
		sep := c.Separate
		if sep == "" {
			sep = "$"
		}
		return &pwdHash{
			hasher: "pbkdf2",
			pbkdf2: &pbkdf2Conf{
				iter:     c.Iter,
				keyLen:   c.KeyLen,
				saltLen:  c.SaltLen,
				separate: sep,
			},
		}, nil
	default:
		return nil, fmt.Errorf("unknown hasher: %s", cfg.Hasher)
	}
}

// NewFastHashingConfDefault returns a FastHashing with sha256 as the default.
//
// Use for integrity checks, fingerprints, or checksums.
// NOT for passwords — no salt or key stretching is applied.
func NewFastHashingConfDefault() FastHashing {
	return &fastHash{
		hasher: "sha256",
		sha256: &sha256Conf{},
		sha512: &sha512Conf{},
	}
}

// NewFastHashingManual returns a FastHashing with the selected algorithm.
//
// Hasher field is required: "sha256" or "sha512".
// Config structs (SHA256Config/SHA512Config) have no parameters.
//
// Example:
//
//	fh, err := hasher.NewFastHashingManual(hasher.FastHashingConfig{
//	    Hasher: "sha512",
//	})
//	if err != nil {
//	    // handle error
//	}
//	h := fh.Hash("hello world")
//	ok := fh.VerifyHash("hello world", h) // true
func NewFastHashingManual(cfg FastHashingConfig) (FastHashing, error) {
	switch cfg.Hasher {
	case "sha256":
		return &fastHash{
			hasher: "sha256",
			sha256: &sha256Conf{},
			sha512: &sha512Conf{},
		}, nil
	case "sha512":
		return &fastHash{
			hasher: "sha512",
			sha256: &sha256Conf{},
			sha512: &sha512Conf{},
		}, nil
	default:
		return nil, fmt.Errorf("unknown hasher: %s", cfg.Hasher)
	}
}
