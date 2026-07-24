package safety

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNewMetadata(t *testing.T) {
	tests := []struct {
		name     string
		email    string
		metadata string
		wantErr  bool
	}{
		{
			name:     "valid metadata with object",
			email:    "user@example.com",
			metadata: `{"project":"Alpha","keys":3}`,
			wantErr:  false,
		},
		{
			name:     "valid metadata with array",
			email:    "user@example.com",
			metadata: `["one","two"]`,
			wantErr:  false,
		},
		{
			name:     "valid metadata with string",
			email:    "user@example.com",
			metadata: `"simple value"`,
			wantErr:  false,
		},
		{
			name:     "invalid JSON metadata",
			email:    "user@example.com",
			metadata: `{broken`,
			wantErr:  true,
		},
		{
			name:     "empty metadata string",
			email:    "user@example.com",
			metadata: ``,
			wantErr:  true,
		},
		{
			name:     "empty email with valid metadata",
			email:    "",
			metadata: `{"key":"value"}`,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := NewMetadata(tt.email, tt.metadata)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error but got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if m.email != tt.email {
				t.Fatalf("email = %q, want %q", m.email, tt.email)
			}
		})
	}
}

func TestUnmarshal(t *testing.T) {
	tests := []struct {
		name     string
		json     string
		want     Metadata
		wantErr  bool
	}{
		{
			name: "valid JSON object",
			json: `{"email":"user@example.com","metadata":{"project":"Alpha"}}`,
			want: Metadata{
				email:    "user@example.com",
				metadata: json.RawMessage(`{"project":"Alpha"}`),
			},
			wantErr: false,
		},
		{
			name: "valid JSON with array metadata",
			json: `{"email":"a@b.com","metadata":[1,2,3]}`,
			want: Metadata{
				email:    "a@b.com",
				metadata: json.RawMessage(`[1,2,3]`),
			},
			wantErr: false,
		},
		{
			name:    "invalid JSON",
			json:    `{bad`,
			want:    Metadata{},
			wantErr: true,
		},
		{
			name:    "missing email field",
			json:    `{"metadata":{"key":"val"}}`,
			want:    Metadata{email: "", metadata: json.RawMessage(`{"key":"val"}`)},
			wantErr: false,
		},
		{
			name:    "missing metadata field",
			json:    `{"email":"x@y.com"}`,
			want:    Metadata{email: "x@y.com", metadata: nil},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Unmarshal([]byte(tt.json))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error but got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.email != tt.want.email {
				t.Fatalf("email = %q, want %q", got.email, tt.want.email)
			}
			if string(got.metadata) != string(tt.want.metadata) {
				t.Fatalf("metadata = %s, want %s", got.metadata, tt.want.metadata)
			}
		})
	}
}

func TestMarshal(t *testing.T) {
	tests := []struct {
		name string
		m    Metadata
		want string
	}{
		{
			name: "object metadata",
			m: Metadata{
				email:    "user@example.com",
				metadata: json.RawMessage(`{"project":"Alpha"}`),
			},
			want: `{"email":"user@example.com","metadata":{"project":"Alpha"}}`,
		},
		{
			name: "array metadata",
			m: Metadata{
				email:    "a@b.com",
				metadata: json.RawMessage(`[1,2,3]`),
			},
			want: `{"email":"a@b.com","metadata":[1,2,3]}`,
		},
		{
			name: "empty metadata with email",
			m: Metadata{
				email:    "x@y.com",
				metadata: nil,
			},
			want: `{"email":"x@y.com","metadata":null}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.m.Marshal()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(got) != tt.want {
				t.Fatalf("got %s, want %s", got, tt.want)
			}
		})
	}
}

func TestMarshalRoundTrip(t *testing.T) {
	tests := []struct {
		name     string
		email    string
		metadata string
	}{
		{
			name:     "object metadata",
			email:    "user@example.com",
			metadata: `{"project":"Alpha","keys":3}`,
		},
		{
			name:     "array metadata",
			email:    "a@b.com",
			metadata: `[{"id":1},{"id":2}]`,
		},
		{
			name:     "string metadata",
			email:    "x@y.com",
			metadata: `"simple"`,
		},
		{
			name:     "nested object",
			email:    "deep@nest.com",
			metadata: `{"level1":{"level2":{"key":"val"}}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original, err := NewMetadata(tt.email, tt.metadata)
			if err != nil {
				t.Fatalf("NewMetadata failed: %v", err)
			}

			data, err := original.Marshal()
			if err != nil {
				t.Fatalf("Marshal failed: %v", err)
			}

			restored, err := Unmarshal(data)
			if err != nil {
				t.Fatalf("Unmarshal failed: %v", err)
			}

			if restored.email != original.email {
				t.Fatalf("email mismatch: got %q, want %q", restored.email, original.email)
			}
			if string(restored.metadata) != string(original.metadata) {
				t.Fatalf("metadata mismatch: got %s, want %s", restored.metadata, original.metadata)
			}
		})
	}
}

func TestMetadataPrint(t *testing.T) {
	// Create a temporary file or buffer to capture output
	// Print writes to stdout via fmt.Printf, so we just verify no error
	m := Metadata{
		email:    "test@example.com",
		metadata: json.RawMessage(`{"key":"value"}`),
	}

	err := m.Print()
	if err != nil {
		t.Fatalf("Print returned unexpected error: %v", err)
	}
}

func TestMetadataPrintInvalidJSON(t *testing.T) {
	// Manually construct Metadata with invalid raw JSON to test error path
	m := Metadata{
		email:    "test@example.com",
		metadata: json.RawMessage(`{broken`),
	}

	err := m.Print()
	if err == nil {
		t.Fatal("expected error for invalid JSON in Print but got nil")
	}
	if !strings.Contains(err.Error(), "invalid") {
		t.Logf("error message: %v", err)
	}
}
