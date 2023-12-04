// Copyright (C) 2023 Mya Pitzeruse
// SPDX-License-Identifier: MIT

package aes

import (
	"context"
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"reflect"

	"gorm.io/gorm/schema"

	"go.pitz.tech/gorm/encryption/database"
	"go.pitz.tech/gorm/encryption/internal"
)

// New constructs a new Serializer using the provided key and computes a fingerprint for the key.
func New(key []byte) *Serializer {
	hash := hmac.New(sha256.New, nil)
	hash.Write(key)

	return &Serializer{
		fingerprint: base64.RawURLEncoding.EncodeToString(hash.Sum(nil)),
		key:         key,
	}
}

// Serializer provides a Gorm serializer capable of encrypting and decrypting database fields using a simple AES block
// cipher. This approach works well for large, generated values that have a high probability of being unique. For more
// common values, take a look at the aesgcm.Serializer implementation.
type Serializer struct {
	fingerprint string
	key         []byte
}

// Scan decrypts the data before setting it on the object.
func (s *Serializer) Scan(ctx context.Context, schema *schema.Field, dst reflect.Value, dbValue interface{}) error {
	data, ok := dbValue.([]byte)
	if !ok {
		return fmt.Errorf("encryption only works on []byte data")
	}

	algorithm, fingerprint, ciphertext := database.ParseField(data)
	switch {
	case fingerprint == "":
		return nil
	case algorithm != internal.AES.ID:
		return fmt.Errorf("expected %s but got: %s", internal.AES.Name, internal.AlgorithmsByID[algorithm].Name)
	}

	block, err := aes.NewCipher(s.key)
	if err != nil {
		return err
	}

	plaintext := make([]byte, len(ciphertext))

	blockSize := block.BlockSize()
	for i := 0; i < len(plaintext); i += blockSize {
		block.Decrypt(plaintext[i:], ciphertext[i:])
	}

	schema.ReflectValueOf(ctx, dst).SetBytes(plaintext)

	return nil
}

// Value encrypts the data before sending it to the database.
func (s *Serializer) Value(_ context.Context, _ *schema.Field, _ reflect.Value, fieldValue interface{}) (interface{}, error) {
	plaintext, ok := fieldValue.([]byte)
	if !ok {
		return nil, fmt.Errorf("encryption only works on []byte data")
	}

	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, len(plaintext))

	blockSize := block.BlockSize()
	for i := 0; i < len(plaintext); i += blockSize {
		block.Encrypt(ciphertext[i:], plaintext[i:])
	}

	return database.FormatField(internal.AES.ID, s.fingerprint, ciphertext), nil
}
