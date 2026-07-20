# Hasher

Go hashing library — password hashing (argon2id, bcrypt, scrypt, pbkdf2) and fast hashing (sha256, sha512) with default and custom configurations.

## Installation

```bash
go get hasher
```

```go
import "hasher"
```

## API

### Password Hashing

The `PasswordHashing` interface provides `Hash` and `Verify` with salt automatically generated from `crypto/rand`.

| Algorithm  | Description                                                                 |
| ---------- | --------------------------------------------------------------------------- |
| `argon2id` | Winner of the Password Hashing Competition. GPU/ASIC resistant. **Default.** |
| `bcrypt`   | Classic, simple, well-tested. 72-byte password limit.                       |
| `scrypt`   | Resistant to hardware attacks. Memory-hard.                                 |
| `pbkdf2`   | NIST standard (HMAC-SHA256). Suitable for enterprise/compliance environments. |

#### Default (argon2id)

```go
ph, err := hasher.NewPasswordHashingConfDefault("argon2")

hashed, err := ph.Hash("secret123")
ok, err := ph.Verify("secret123", hashed) // true
```

#### Manual (choose one)

```go
ph, err := hasher.NewPasswordHashingManual(hasher.PasswordHashingConfig{
    Hasher: "bcrypt",
    Bcrypt: &hasher.BcryptConfig{Cost: 12},
})
if err != nil {
    panic(err)
}

hashed, err := ph.Hash("secret123")
ok, err := ph.Verify("secret123", hashed)
```

#### Output format

```
argon2/scrypt/pbkdf2:  "algo$base64_salt$base64_hash"
bcrypt:                "$2a$10$..."  (native format, no extra prefix)
```

### Fast Hashing

The `FastHashing` interface provides `Hash`, `HashBytes`, and `VerifyHash`. **No salt** — suitable only for integrity checks, fingerprints, or checksums.

| Algorithm | Output                          |
| --------- | ------------------------------- |
| `sha256`  | 64-character hex string.        |
| `sha512`  | 128-character hex string.       |

#### Default (sha256)

```go
fh, err := hasher.NewFastHashingConfDefault("sha256")

h := fh.Hash("hello")
ok := fh.VerifyHash("hello", h) // true
```

#### Manual

```go
fh, err := hasher.NewFastHashingManual(hasher.FastHashingConfig{
    Hasher: "sha512",
})

h := fh.Hash("some data to hash")
```

## Configuration

### Default password hashing

| Algorithm | Parameters                                                           |
| --------- | -------------------------------------------------------------------- |
| argon2    | time=1, memory=64MB, threads=4, keyLen=32, saltLen=16                |
| bcrypt    | cost=10                                                              |
| scrypt    | N=32768, R=8, P=1, keyLen=32, saltLen=16                             |
| pbkdf2    | iter=600000, keyLen=32, saltLen=16                                   |

### Manual config structs

| Struct            | Fields                                                                     |
| ----------------- | -------------------------------------------------------------------------- |
| `Argon2Config`    | `Time`, `Memory` (KiB), `Threads`, `KeyLen`, `SaltLen`, `Separate`         |
| `BcryptConfig`    | `Cost` (4–31, 0=default 10), `Separate`                                    |
| `ScryptConfig`    | `N`, `R`, `P`, `KeyLen`, `SaltLen`, `Separate`                             |
| `PBKDF2Config`    | `Iter`, `KeyLen`, `SaltLen`, `Separate`                                    |
| `SHA256Config`    | *(no parameters)*                                                           |
| `SHA512Config`    | *(no parameters)*                                                           |

## Notes

- **bcrypt** truncates passwords longer than 72 bytes. Use argon2id or scrypt if accepting long passwords.
- **Fast hashing is not for passwords** — there is no salt or key stretching. Hashes are deterministic (`hash("a")` always produces the same output).
- All salts are generated from `crypto/rand` (CSPRNG).
- `Verify` automatically detects the algorithm from the hash format — you can switch algorithms without migrating all stored data.
