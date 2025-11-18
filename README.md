# Quantum-Backed Secure Note CLI

Command-line application for Arch Linux that captures a user message, derives strong credentials with the aid of a quantum random number generator (QRNG), and stores a one-way encrypted representation of the message. The final ciphertext is a fixed 512-character hex string derived with SHA-512 based primitives and QRNG entropy.

## Build & Test

```bash
make          # build the qrng_encrypt binary
make test     # run unit and integration tests
make clean    # remove build artefacts
```

Dependencies: `gcc` (C11 compliant), `curl` (used by the QRNG client), and standard POSIX utilities available on Arch Linux.

## Usage

```bash
./qrng_encrypt
```

Workflow:
- Enter your name (alphanumeric, `_` or `-`). A file `<username>.txt` is created.
- Provide a short message to protect.
- Choose to supply your own password (must be ≥12 chars with upper, lower, digit, special) or let the tool fetch a quantum-generated password.
- The tool writes the original message, derives keys using SHA-512, QRNG entropy, and PBKDF2-style hardening, then replaces the file contents with the 512-character ciphertext.

The generated password is echoed exactly once if QRNG mode is selected—store it securely.

## Architecture

```
src/
  main.c          // Orchestrates the CLI workflow
  input.*         // Hardened user input helpers
  file_ops.*      // Safe file creation/replacement routines
  qrng.*          // Quantum RNG API integration with /dev/urandom fallback
  crypto.*        // SHA-512 hashing, PBKDF2-style KDF, HKDF-like expansion
  sha512.*        // Standalone SHA-512 + HMAC implementation
  utils.*         // Sanitisation, encoding, secure memory wiping
tests/
  test_runner.c   // Aggregates test suites
  test_input.c    // Username/password validation tests
  test_file_ops.c // Safe file handling tests
  test_crypto.c   // Hashing/KDF/encryption determinism tests
```

## Security Notes

- SHA-512 is implemented locally to avoid external dependencies; HMAC and PBKDF2-style derivation reuse this primitive.
- QRNG entropy is fetched from the Australian National University API via `curl`. Set `QRNG_OFFLINE=1` to force a `/dev/urandom` fallback (used during automated tests).
- Sensitive buffers (passwords, keys, ciphertext) are wiped with `secure_zero` after use.
- Password prompts disable terminal echo to reduce shoulder-surfing risk.

## Extending

- Persist salts or metadata alongside ciphertext if future decryption/validation modes are required.
- Replace the minimal HTTP client with a libcurl-based implementation when external libraries are permissible.
- Consider storing hashes of usernames/messages for auditing or multi-note support.

## Deployment

The project is GNU Make driven and produces a single statically linked CLI binary suitable for packaging or further automation scripts on Arch Linux systems.
