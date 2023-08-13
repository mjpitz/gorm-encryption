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
	"encoding/base64"
	"encoding/json"
	"github.com/matryer/is"
	"testing"

	"github.com/glebarez/sqlite"
	"go.pitz.tech/gorm/encryption"
	"gorm.io/gorm"
)

type TypesAESGCM struct {
	Bytes  []byte `gorm:"type:varbinary;serializer:aes-gcm"`
	String string `gorm:"type:varbinary;serializer:aes-gcm"`

	Int   int   `gorm:"type:varbinary;serializer:aes-gcm"`
	Int8  int8  `gorm:"type:varbinary;serializer:aes-gcm"`
	Int16 int16 `gorm:"type:varbinary;serializer:aes-gcm"`
	Int32 int32 `gorm:"type:varbinary;serializer:aes-gcm"`
	Int64 int64 `gorm:"type:varbinary;serializer:aes-gcm"`

	Uint   uint   `gorm:"type:varbinary;serializer:aes-gcm"`
	Uint8  uint8  `gorm:"type:varbinary;serializer:aes-gcm"`
	Uint16 uint16 `gorm:"type:varbinary;serializer:aes-gcm"`
	Uint32 uint32 `gorm:"type:varbinary;serializer:aes-gcm"`
	Uint64 uint64 `gorm:"type:varbinary;serializer:aes-gcm"`

	Float32 float32 `gorm:"type:varbinary;serializer:aes-gcm"`
	Float64 float64 `gorm:"type:varbinary;serializer:aes-gcm"`
}

type testAESGCMRecord struct {
	ID int `gorm:"primaryKey;autoIncrement"`

	TypesAESGCM
	Struct TypesAESGCM `gorm:"type:varbinary;serializer:aes-gcm"`
}

func TestAESGCM(t *testing.T) {
	is := is.New(t)

	// setup aes key and GORM serializer

	key, err := encryption.GenerateKey()
	is.NoErr(err)

	// setup in-memory database
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"))
	is.NoErr(err)

	// setup encryption
	err = encryption.Register(db,
		encryption.WithKey(key),
		encryption.WithMigration(),
		encryption.WithMarshaling(json.Marshal, json.Unmarshal),
	)
	is.NoErr(err)

	// migrate core schema

	err = db.AutoMigrate(testAESGCMRecord{})
	is.NoErr(err)

	// test encryption and decryption

	random, err := encryption.GenerateKey()
	is.NoErr(err)

	expected := TypesAESGCM{
		Bytes:  random,
		String: base64.StdEncoding.EncodeToString(random),
		Int:    127,
		Int8:   127,
		Int16:  127,
		Int32:  127,
		Int64:  127,

		Uint:   127,
		Uint8:  127,
		Uint16: 127,
		Uint32: 127,
		Uint64: 127,

		Float32: 127,
		Float64: 127,
	}

	err = db.Create(&testAESGCMRecord{
		TypesAESGCM: expected,
		Struct:      expected,
	}).Error
	is.NoErr(err)

	decoded := &testAESGCMRecord{}
	err = db.First(decoded).Error
	is.NoErr(err)

	is.Equal(expected, decoded.TypesAESGCM)
	is.Equal(expected, decoded.Struct)
}
