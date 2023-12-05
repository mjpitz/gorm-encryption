// Copyright (C) 2023 Mya Pitzeruse
// SPDX-License-Identifier: MIT

package database_test

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/matryer/is"

	"go.pitz.tech/gorm/encryption/database"
	"go.pitz.tech/gorm/encryption/internal"
)

func TestField(t *testing.T) {
	i := is.New(t)

	{
		empty := []byte{}
		algorithm, fingerprint, ciphertext := database.ParseField(empty)
		i.Equal(internal.Unknown.ID, algorithm)
		i.Equal("", fingerprint)
		i.Equal(ciphertext, empty)
	}

	{
		expectedCiphertext := make([]byte, 64)
		_, err := rand.Read(expectedCiphertext)
		if err != nil {
			t.Fatalf("failed to read ciphertext: %v", err)
		}

		hash := sha256.Sum256(expectedCiphertext)
		expectedFingerprint := hex.EncodeToString(hash[:])

		field := database.FormatField(internal.AES.ID, expectedFingerprint, expectedCiphertext)
		algorithm, fingerprint, ciphertext := database.ParseField(field)

		i.Equal(internal.AES.ID, algorithm)
		i.Equal(expectedFingerprint, fingerprint)
		i.Equal(expectedCiphertext, ciphertext)
	}
}

func TestKey(t *testing.T) {
	i := is.New(t)

	i.Equal("encryption_keys", database.Key{}.TableName())
}
