package port

type Cipher interface {
	Encrypt(b []byte, passkey string) (string, error)
	Decrypt(seed string, passkey string) ([]byte, error)
}
