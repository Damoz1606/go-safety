package application

import (
	"context"
	"fmt"

	"github.com/Damoz1606/go-safety/internal/safety"
	"github.com/Damoz1606/go-safety/internal/safety/port"
)

type EncryptInput struct {
	Email    string
	Passkey  string
	Metadata string
}

type EncryptUseCase interface {
	Execute(ctx context.Context, input EncryptInput) error
}

type EncryptUseCaseDeps struct {
	Cipher port.Cipher
}

type encryptUseCase struct {
	cipher port.Cipher
}

func NewEncryptUseCase(deps EncryptUseCaseDeps) EncryptUseCase {
	return &encryptUseCase{
		cipher: deps.Cipher,
	}
}

func (e encryptUseCase) Execute(ctx context.Context, input EncryptInput) error {
	data, err := safety.NewMetadata(input.Email, input.Metadata)

	if err != nil {
		return err
	}

	jsonBytes, err := data.Marshal()
	if err != nil {
		return err
	}

	seed, err := e.cipher.Encrypt(jsonBytes, input.Passkey)
	if err != nil {
		return err
	}

	fmt.Printf("Seed: %s\n", seed)

	return nil
}
