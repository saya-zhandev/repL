package main

import (
	"repl/internal/encryptor"
	"repl/internal/ledger"
	"repl/internal/zkcircuit"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncryptionRoundTrip(t *testing.T) {
	enc, err := encryptor.NewAES256GCM("0123456789abcdef0123456789abcdef")
	assert.NoError(t, err)

	plaintext := []byte("test student data")
	ciphertext, err := enc.Encrypt(plaintext)
	assert.NoError(t, err)

	decrypted, err := enc.Decrypt(ciphertext)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestLedgerHashChain(t *testing.T) {
	l := ledger.NewLocalLedger()
	l.Append("commitment1")
	l.Append("commitment2")
	l.Append("commitment3")

	valid, err := l.VerifyChain()
	assert.NoError(t, err)
	assert.True(t, valid)
}

func TestZKCircuitValid(t *testing.T) {
	prover, err := zkcircuit.NewGPAThresholdProver()
	assert.NoError(t, err)

	// Test valid case: GPA=3.8 >= 3.5 should pass
	verified, err := prover.VerifyGPAThreshold(3.8, 3.5)
	assert.NoError(t, err)
	assert.True(t, verified)

	// Test invalid case: GPA=3.2 < 3.5 should fail
	verified, err = prover.VerifyGPAThreshold(3.2, 3.5)
	assert.NoError(t, err)
	assert.False(t, verified)
}
