package safety

import (
	"bytes"
	"encoding/json"
	"fmt"
)

type Metadata struct {
	email    string
	metadata json.RawMessage
}

type MetadataJSON struct {
	Email    string          `json:"email"`
	Metadata json.RawMessage `json:"metadata"`
}

func NewMetadata(
	email string,
	metadata string,
) (*Metadata, error) {

	var metadataObj json.RawMessage
	if err := json.Unmarshal([]byte(metadata), &metadataObj); err != nil {
		return nil, err
	}

	return &Metadata{
		email:    email,
		metadata: metadataObj,
	}, nil
}

func Unmarshal(jsonBytes []byte) (Metadata, error) {
	var data MetadataJSON
	if err := json.Unmarshal(jsonBytes, &data); err != nil {
		return Metadata{}, err
	}

	return Metadata{
		email:    data.Email,
		metadata: data.Metadata,
	}, nil
}

func (m Metadata) Marshal() ([]byte, error) {
	value := MetadataJSON{
		Email:    m.email,
		Metadata: m.metadata,
	}

	return json.Marshal(value)

}

func (m Metadata) Print() error {
	var prettyMetadata bytes.Buffer
	if err := json.Indent(&prettyMetadata, m.metadata, "", "  "); err != nil {
		return err
	}

	fmt.Printf("Email:    %s\n", m.email)
	fmt.Printf("Metadata: %s\n", prettyMetadata.String())

	return nil
}
