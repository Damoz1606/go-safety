package application

import "github.com/Damoz1606/go-safety/internal/safety/port"

// mockCipher is a test double for port.Cipher used across application tests.
type mockCipher struct {
	encryptFn func(b []byte, passkey string) (string, error)
	decryptFn func(seed string, passkey string) ([]byte, error)
}

func (m mockCipher) Encrypt(b []byte, passkey string) (string, error) {
	return m.encryptFn(b, passkey)
}

func (m mockCipher) Decrypt(seed string, passkey string) ([]byte, error) {
	return m.decryptFn(seed, passkey)
}

// Compile-time check that mockCipher implements port.Cipher.
var _ port.Cipher = mockCipher{}
