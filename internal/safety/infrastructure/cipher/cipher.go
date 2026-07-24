package cipher

import (
	"crypto/aes"
	cryptoCipher "crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"

	"github.com/Damoz1606/go-safety/internal/safety/port"
	"golang.org/x/crypto/argon2"
)

type Cipher struct {
	saltLen      int16
	nonceLen     int16
	keyLen       uint32
	argonTime    uint32
	argonMemory  uint32
	argonThreads uint8
}

type NewCipherDeps struct {
	SaltLen      int16
	NonceLen     int16
	KeyLen       uint32
	ArgonTime    uint32
	ArgonMemory  uint32
	ArgonThreads uint8
}

func NewCipher(deps NewCipherDeps) port.Cipher {
	return &Cipher{
		saltLen:      deps.SaltLen,
		nonceLen:     deps.NonceLen,
		keyLen:       deps.KeyLen,
		argonTime:    deps.ArgonTime,
		argonMemory:  deps.ArgonMemory,
		argonThreads: deps.ArgonThreads,
	}
}

func (c Cipher) Encrypt(b []byte, passkey string) (string, error) {
	salt := make([]byte, c.saltLen)
	nonce := make([]byte, c.nonceLen)

	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}

	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	key := c.deriveKey(passkey, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cryptoCipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	cipherText := gcm.Seal(nil, nonce, b, nil)

	output := append(salt, nonce...)
	output = append(output, cipherText...)

	return base64.StdEncoding.EncodeToString(output), nil
}

func (c Cipher) Decrypt(seed string, passkey string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(seed)
	if err != nil {
		return nil, fmt.Errorf("base64 decode failed: %w", err)
	}

	saltLen := int(c.saltLen)
	nonceLen := int(c.nonceLen)

	if len(data) < saltLen+nonceLen {
		return nil, fmt.Errorf("seed too short")
	}

	salt := data[:saltLen]
	rest := data[saltLen:]

	if len(rest) < nonceLen {
		return nil, fmt.Errorf("ciphertext too short for nonce")
	}

	nonce := rest[:nonceLen]
	ciphertext := rest[nonceLen:]

	key := c.deriveKey(passkey, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes new cipher failed: %w", err)
	}

	gcm, err := cryptoCipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm creation failed: %w", err)
	}

	plainbytes, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("gcm open failed: %w", err)
	}

	return plainbytes, nil
}

func (c Cipher) deriveKey(passkey string, salt []byte) []byte {
	return argon2.IDKey([]byte(passkey), salt, c.argonTime, c.argonMemory, c.argonThreads, c.keyLen)
}
