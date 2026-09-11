package encryptor

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"io"
)

type AESEncryptor struct {
	gcm cipher.AEAD
}

func NewAES256GCM(key string) (*AESEncryptor, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &AESEncryptor{gcm: gcm}, nil
}

func (a *AESEncryptor) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, a.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return a.gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func (a *AESEncryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	nonceSize := a.gcm.NonceSize()
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return a.gcm.Open(nil, nonce, ciphertext, nil)
}

func ComputeSHA256Commitment(data []byte) string {
	hash := sha256.Sum256(data)
	return string(hash[:])
}
