package application

import (
	"context"
	"errors"
	"testing"

	"github.com/Damoz1606/go-safety/internal/safety/port"
)

func TestEncryptUseCase_Execute(t *testing.T) {
	tests := []struct {
		name       string
		input      EncryptInput
		mockCipher port.Cipher
		wantErr    bool
		errMsg     string
	}{
		{
			name: "successful encryption",
			input: EncryptInput{
				Email:    "user@example.com",
				Passkey:  "secret123",
				Metadata: `{"project":"Alpha"}`,
			},
			mockCipher: mockCipher{
				encryptFn: func(b []byte, passkey string) (string, error) {
					return "encrypted-seed-abc", nil
				},
			},
			wantErr: false,
		},
		{
			name: "invalid metadata JSON",
			input: EncryptInput{
				Email:    "user@example.com",
				Passkey:  "secret123",
				Metadata: `{broken`,
			},
			mockCipher: mockCipher{
				encryptFn: func(b []byte, passkey string) (string, error) {
					return "", nil
				},
			},
			wantErr: true,
		},
		{
			name: "cipher encrypt error",
			input: EncryptInput{
				Email:    "user@example.com",
				Passkey:  "secret123",
				Metadata: `{"project":"Alpha"}`,
			},
			mockCipher: mockCipher{
				encryptFn: func(b []byte, passkey string) (string, error) {
					return "", errors.New("cipher failure")
				},
			},
			wantErr: true,
			errMsg:  "cipher failure",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uc := NewEncryptUseCase(EncryptUseCaseDeps{
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

func TestEncryptUseCase_PasskeyForwarding(t *testing.T) {
	// Verify the passkey is forwarded to the cipher
	var receivedPasskey string
	mock := mockCipher{
		encryptFn: func(b []byte, passkey string) (string, error) {
			receivedPasskey = passkey
			return "seed", nil
		},
	}

	uc := NewEncryptUseCase(EncryptUseCaseDeps{Cipher: mock})
	input := EncryptInput{
		Email:    "user@example.com",
		Passkey:  "my-secret-key",
		Metadata: `{"key":"value"}`,
	}

	err := uc.Execute(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if receivedPasskey != "my-secret-key" {
		t.Fatalf("passkey = %q, want %q", receivedPasskey, "my-secret-key")
	}
}
