package cli

import (
	"testing"
)

func TestValidateEncryptArgs(t *testing.T) {
	makeStr := func(s string) *string { return &s }

	tests := []struct {
		name     string
		email    *string
		passkey  *string
		metadata *string
		wantErr  bool
		errMsg   string
	}{
		{
			name:     "all valid",
			email:    makeStr("user@example.com"),
			passkey:  makeStr("secret123"),
			metadata: makeStr(`{"project":"Alpha"}`),
			wantErr:  false,
		},
		{
			name:     "missing email",
			email:    makeStr(""),
			passkey:  makeStr("secret123"),
			metadata: makeStr(`{"key":"val"}`),
			wantErr:  true,
			errMsg:   "Error: encrypt requires -email, -passkey, -metadata",
		},
		{
			name:     "missing passkey",
			email:    makeStr("user@example.com"),
			passkey:  makeStr(""),
			metadata: makeStr(`{"key":"val"}`),
			wantErr:  true,
			errMsg:   "Error: encrypt requires -email, -passkey, -metadata",
		},
		{
			name:     "missing metadata",
			email:    makeStr("user@example.com"),
			passkey:  makeStr("secret123"),
			metadata: makeStr(""),
			wantErr:  true,
			errMsg:   "Error: encrypt requires -email, -passkey, -metadata",
		},
		{
			name:     "all empty",
			email:    makeStr(""),
			passkey:  makeStr(""),
			metadata: makeStr(""),
			wantErr:  true,
			errMsg:   "Error: encrypt requires -email, -passkey, -metadata",
		},
		{
			name:     "invalid JSON metadata",
			email:    makeStr("user@example.com"),
			passkey:  makeStr("secret123"),
			metadata: makeStr(`{broken`),
			wantErr:  true,
			errMsg:   "Error: -metadata must be valid JSON",
		},
		{
			name:     "metadata is valid but not object",
			email:    makeStr("user@example.com"),
			passkey:  makeStr("secret123"),
			metadata: makeStr(`"just a string"`),
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateEncryptArgs(tt.email, tt.passkey, tt.metadata)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error but got nil")
				}
				if err.Error() != tt.errMsg {
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

func TestValidateDecryptArgs(t *testing.T) {
	makeStr := func(s string) *string { return &s }

	tests := []struct {
		name    string
		seed    *string
		passkey *string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "all valid",
			seed:    makeStr("encrypted-seed-123"),
			passkey: makeStr("secret123"),
			wantErr: false,
		},
		{
			name:    "missing seed",
			seed:    makeStr(""),
			passkey: makeStr("secret123"),
			wantErr: true,
			errMsg:  "Error: decrypt requires -seed, -passkey",
		},
		{
			name:    "missing passkey",
			seed:    makeStr("encrypted-seed-123"),
			passkey: makeStr(""),
			wantErr: true,
			errMsg:  "Error: decrypt requires -seed, -passkey",
		},
		{
			name:    "both missing",
			seed:    makeStr(""),
			passkey: makeStr(""),
			wantErr: true,
			errMsg:  "Error: decrypt requires -seed, -passkey",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDecryptArgs(tt.seed, tt.passkey)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error but got nil")
				}
				if err.Error() != tt.errMsg {
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
