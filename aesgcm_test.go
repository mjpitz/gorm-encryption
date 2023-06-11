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

package encryption_test

import (
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/require"
	"go.pitz.tech/gorm/encryption"
	"gorm.io/gorm"
)

type testAESGCMRecord struct {
	ID  int    `gorm:"primaryKey;autoIncrement"`
	Key []byte `gorm:"serializer:aes-gcm"`
}

func TestAESGCM(t *testing.T) {
	// setup aes key and GORM serializer

	key, err := encryption.GenerateKey()
	require.NoError(t, err)

	// setup in-memory database
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"))
	require.NoError(t, err)

	// setup encryption
	err = encryption.Register(db, encryption.WithKey(key), encryption.WithMigration())
	require.NoError(t, err)

	// migrate core schema

	err = db.AutoMigrate(testAESGCMRecord{})
	require.NoError(t, err)

	// test encryption and decryption

	expected, err := encryption.GenerateKey()
	require.NoError(t, err)

	err = db.Create(&testAESGCMRecord{Key: expected}).Error
	require.NoError(t, err)

	decoded := &testAESGCMRecord{}
	err = db.First(decoded).Error
	require.NoError(t, err)

	require.Equal(t, expected, decoded.Key)
}
