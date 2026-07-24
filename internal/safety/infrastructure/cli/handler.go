package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"

	"github.com/Damoz1606/go-safety/internal/safety/application"
	"github.com/Damoz1606/go-safety/internal/safety/infrastructure/cipher"
)

func Handle(ctx context.Context) error {

	var (
		mode     = flag.String("mode", "", "Action: encrypt or decrypt")
		email    = flag.String("email", "", "Email address")
		passkey  = flag.String("passkey", "", "Passkey for encryption/decryption")
		metadata = flag.String("metadata", "", "Metadata JSON object (e.g., '{\"key\":\"value\"}')")
		seed     = flag.String("seed", "", "Seed to encrypt")
	)
	flag.Parse()

	c := cipher.NewCipher(cipher.NewCipherDeps{
		SaltLen:      16,
		NonceLen:     12,
		KeyLen:       32,
		ArgonTime:    3,
		ArgonMemory:  64 * 1024,
		ArgonThreads: 4,
	})

	encrypt := application.NewEncryptUseCase(application.EncryptUseCaseDeps{
		Cipher: c,
	})

	decrypt := application.NewDecryptUseCase(application.DecryptUseCaseDeps{
		Cipher: c,
	})

	switch *mode {
	case "encrypt":

		if err := validateEncryptArgs(email, passkey, metadata); err != nil {
			return err
		}

		return encrypt.Execute(ctx, application.EncryptInput{
			Email:    *email,
			Passkey:  *passkey,
			Metadata: *metadata,
		})
	case "decrypt":

		if err := validateDecryptArgs(seed, passkey); err != nil {
			return err
		}

		return decrypt.Execute(ctx, application.DecryptInput{
			Seed:    *seed,
			Passkey: *passkey,
		})
	default:
		printUsage()
		return nil
	}
}

func validateEncryptArgs(email, passkey, metadata *string) error {
	if *email == "" || *passkey == "" || *metadata == "" {
		return errors.New("Error: encrypt requires -email, -passkey, -metadata")
	}

	if !json.Valid([]byte(*metadata)) {
		return errors.New("Error: -metadata must be valid JSON")
	}

	return nil
}

func validateDecryptArgs(seed, passkey *string) error {
	if *seed == "" || *passkey == "" {
		return errors.New("Error: decrypt requires -seed, -passkey")
	}

	return nil
}

func printUsage() {
	fmt.Println("Usage:")
	fmt.Println("  Encrypt: go run . -mode=encrypt -email='a@b.com' -passkey='secret' -metadata='{\"project\":\"Alpha\",\"keys\":3}'")
	fmt.Println("  Decrypt: go run . -mode=decrypt -seed='SEED...' -passkey='secret' [-raw]")
}
