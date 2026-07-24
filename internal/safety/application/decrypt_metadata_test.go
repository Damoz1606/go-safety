package application

import (
	"context"
	"errors"
	"testing"

	"github.com/Damoz1606/go-safety/internal/safety/port"
)

func TestDecryptUseCase_Execute(t *testing.T) {
	tests := []struct {
		name       string
		input      DecryptInput
		mockCipher port.Cipher
		wantErr    bool
		errMsg     string
	}{
		{
			name: "successful decryption",
			input: DecryptInput{
				Seed:    "encrypted-seed-abc",
				Passkey: "secret123",
			},
			mockCipher: mockCipher{
				decryptFn: func(seed string, passkey string) ([]byte, error) {
					return []byte(`{"email":"user@example.com","metadata":{"project":"Alpha"}}`), nil
				},
			},
			wantErr: false,
		},
		{
			name: "cipher decrypt error",
			input: DecryptInput{
				Seed:    "bad-seed",
				Passkey: "wrong-key",
			},
			mockCipher: mockCipher{
				decryptFn: func(seed string, passkey string) ([]byte, error) {
					return nil, errors.New("decryption failed: invalid key")
				},
			},
			wantErr: true,
			errMsg:  "decryption failed: invalid key",
		},
		{
			name: "cipher returns invalid JSON",
			input: DecryptInput{
				Seed:    "corrupted-seed",
				Passkey: "secret123",
			},
			mockCipher: mockCipher{
				decryptFn: func(seed string, passkey string) ([]byte, error) {
					return []byte(`{broken json`), nil
				},
			},
			wantErr: true,
		},
		{
			name: "cipher returns non-metadata JSON",
			input: DecryptInput{
				Seed:    "wrong-data-seed",
				Passkey: "secret123",
			},
			mockCipher: mockCipher{
				decryptFn: func(seed string, passkey string) ([]byte, error) {
					return []byte(`"just a string"`), nil
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uc := NewDecryptUseCase(DecryptUseCaseDeps{
				Cipher: tt.mockCipher,
			})

			err := uc.Execute(context.Background(), tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error but got nil")
				}
				if tt.errMsg != "" && err.Error() != tt.errMsg {
					t.Fatalf("error = %q, want %q", err.Error(), tt.errMsg)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestDecryptUseCase_PasskeyForwarding(t *testing.T) {
	var receivedPasskey string
	mock := mockCipher{
		decryptFn: func(seed string, passkey string) ([]byte, error) {
			receivedPasskey = passkey
			return []byte(`{"email":"x@y.com","metadata":{"key":"val"}}`), nil
		},
	}

	uc := NewDecryptUseCase(DecryptUseCaseDeps{Cipher: mock})
	input := DecryptInput{
		Seed:    "some-seed",
		Passkey: "forwarded-key",
	}

	err := uc.Execute(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if receivedPasskey != "forwarded-key" {
		t.Fatalf("passkey = %q, want %q", receivedPasskey, "forwarded-key")
	}
}
