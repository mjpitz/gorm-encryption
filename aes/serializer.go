// Copyright (c) 2023 Mya Pitzeruse
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
// OR OTHER DEALINGS IN THE SOFTWARE.

package aes

import (
	"context"
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"reflect"

	"go.pitz.tech/gorm/encryption/database"
	"go.pitz.tech/gorm/encryption/internal"
	"gorm.io/gorm/schema"
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
