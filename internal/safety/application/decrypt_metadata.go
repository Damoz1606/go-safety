package application

import (
	"context"

	"github.com/Damoz1606/go-safety/internal/safety"
	"github.com/Damoz1606/go-safety/internal/safety/port"
)

type DecryptInput struct {
	Seed    string
	Passkey string
}

type DecryptOutput struct{}

type DecryptUseCase interface {
	Execute(ctx context.Context, input DecryptInput) error
}

type DecryptUseCaseDeps struct {
	Cipher port.Cipher
}

type decryptUseCase struct {
	cipher port.Cipher
}

func NewDecryptUseCase(deps DecryptUseCaseDeps) DecryptUseCase {
	return &decryptUseCase{
		cipher: deps.Cipher,
	}
}

func (e decryptUseCase) Execute(ctx context.Context, input DecryptInput) error {

	jsonBytes, err := e.cipher.Decrypt(input.Seed, input.Passkey)

	if err != nil {
		return err
	}

	data, err := safety.Unmarshal(jsonBytes)
	if err != nil {
		return err
	}

	err = data.Print()
	if err != nil {
		return err
	}

	return nil
}
