package cipher

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestCipher_EncryptDecrypt_RoundTrip(t *testing.T) {
	c := NewCipher(NewCipherDeps{
		SaltLen:      16,
		NonceLen:     12,
		KeyLen:       32,
		ArgonTime:    3,
		ArgonMemory:  64 * 1024,
		ArgonThreads: 4,
	})

	tests := []struct {
		name    string
		data    []byte
		passkey string
	}{
		{
			name:    "simple text",
			data:    []byte("hello world"),
			passkey: "my-secret",
		},
		{
			name:    "JSON payload",
			data:    []byte(`{"email":"user@example.com","metadata":{"project":"Alpha"}}`),
			passkey: "secure-passphrase",
		},
		{
			name:    "binary data",
			data:    []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD},
			passkey: "binary-key",
		},
		{
			name:    "empty data",
			data:    []byte{},
			passkey: "empty-test",
		},
		{
			name:    "large payload",
			data:    bytes.Repeat([]byte("data"), 1000),
			passkey: "large-key",
		},
		{
			name:    "unicode passkey",
			data:    []byte("sensitive content"),
			passkey: "contraseña-ñandú-日本語",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seed, err := c.Encrypt(tt.data, tt.passkey)
			if err != nil {
				t.Fatalf("encrypt failed: %v", err)
			}

			if seed == "" {
				t.Fatal("encrypt returned empty seed")
			}

			decrypted, err := c.Decrypt(seed, tt.passkey)
			if err != nil {
				t.Fatalf("decrypt failed: %v", err)
			}

			if !bytes.Equal(decrypted, tt.data) {
				t.Fatalf("round-trip mismatch: got %q, want %q", decrypted, tt.data)
			}
		})
	}
}

func TestCipher_Decrypt_WrongPasskey(t *testing.T) {
	c := NewCipher(NewCipherDeps{
		SaltLen:      16,
		NonceLen:     12,
		KeyLen:       32,
		ArgonTime:    3,
		ArgonMemory:  64 * 1024,
		ArgonThreads: 4,
	})

	data := []byte("secret message")
	seed, err := c.Encrypt(data, "correct-key")
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	_, err = c.Decrypt(seed, "wrong-key")
	if err == nil {
		t.Fatal("expected error with wrong passkey but got nil")
	}
}

func TestCipher_Decrypt_TamperedSeed(t *testing.T) {
	c := NewCipher(NewCipherDeps{
		SaltLen:      16,
		NonceLen:     12,
		KeyLen:       32,
		ArgonTime:    3,
		ArgonMemory:  64 * 1024,
		ArgonThreads: 4,
	})

	data := []byte("tamper test")
	seed, err := c.Encrypt(data, "pass")
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	// Tamper: flip one byte in the ciphertext portion.
	// seed is base64-encoded salt+nonce+ciphertext. Decode, modify a byte
	// deep in the ciphertext region, re-encode.
	raw, err := base64.StdEncoding.DecodeString(seed)
	if err != nil {
		t.Fatalf("failed to decode seed: %v", err)
	}
	// Flip the last byte (which is in the ciphertext, past salt+nonce=28 bytes)
	if len(raw) > 28 {
		raw[len(raw)-1] ^= 0xFF
	}
	tamperedSeed := base64.StdEncoding.EncodeToString(raw)

	_, err = c.Decrypt(tamperedSeed, "pass")
	if err == nil {
		t.Fatal("expected error for tampered seed")
	}
}

func TestCipher_Decrypt_TruncatedSeed(t *testing.T) {
	c := NewCipher(NewCipherDeps{
		SaltLen:      16,
		NonceLen:     12,
		KeyLen:       32,
		ArgonTime:    3,
		ArgonMemory:  64 * 1024,
		ArgonThreads: 4,
	})

	_, err := c.Decrypt("dG9vLXNob3J0", "pass") // base64 of "too-short"
	if err == nil {
		t.Fatal("expected error for truncated seed")
	}
}

func TestCipher_Decrypt_EmptySeed(t *testing.T) {
	c := NewCipher(NewCipherDeps{
		SaltLen:      16,
		NonceLen:     12,
		KeyLen:       32,
		ArgonTime:    3,
		ArgonMemory:  64 * 1024,
		ArgonThreads: 4,
	})

	_, err := c.Decrypt("", "pass")
	if err == nil {
		t.Fatal("expected error for empty seed")
	}
}

func TestCipher_Encrypt_Determinism(t *testing.T) {
	c := NewCipher(NewCipherDeps{
		SaltLen:      16,
		NonceLen:     12,
		KeyLen:       32,
		ArgonTime:    3,
		ArgonMemory:  64 * 1024,
		ArgonThreads: 4,
	})

	data := []byte("determinism check")

	seed1, err := c.Encrypt(data, "pass")
	if err != nil {
		t.Fatalf("first encrypt failed: %v", err)
	}

	seed2, err := c.Encrypt(data, "pass")
	if err != nil {
		t.Fatalf("second encrypt failed: %v", err)
	}

	// Each encryption should produce a different seed due to random salt/nonce
	// but both should decrypt to the same data
	if seed1 == seed2 {
		t.Fatal("consecutive encryptions should produce different seeds due to random salt/nonce")
	}

	dec1, _ := c.Decrypt(seed1, "pass")
	dec2, _ := c.Decrypt(seed2, "pass")

	if !bytes.Equal(dec1, data) || !bytes.Equal(dec2, data) {
		t.Fatal("both seeds should decrypt to original data")
	}
}

func TestCipher_CustomConfig(t *testing.T) {
	tests := []struct {
		name string
		deps NewCipherDeps
	}{
		{
			name: "minimum config",
			deps: NewCipherDeps{
				SaltLen:      8,
				NonceLen:     12,
				KeyLen:       32,
				ArgonTime:    1,
				ArgonMemory:  32 * 1024,
				ArgonThreads: 1,
			},
		},
		{
			name: "higher security config",
			deps: NewCipherDeps{
				SaltLen:      32,
				NonceLen:     12,
				KeyLen:       32,
				ArgonTime:    4,
				ArgonMemory:  128 * 1024,
				ArgonThreads: 8,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCipher(tt.deps)
			data := []byte("custom config test")

			seed, err := c.Encrypt(data, "pass")
			if err != nil {
				t.Fatalf("encrypt failed: %v", err)
			}

			decrypted, err := c.Decrypt(seed, "pass")
			if err != nil {
				t.Fatalf("decrypt failed: %v", err)
			}

			if !bytes.Equal(decrypted, data) {
				t.Fatal("round-trip mismatch with custom config")
			}
		})
	}
}
