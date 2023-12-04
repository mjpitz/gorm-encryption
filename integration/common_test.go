// Copyright (C) 2023 Mya Pitzeruse
// SPDX-License-Identifier: MIT

package integration_test

import (
	"encoding/base64"
	"encoding/json"

	"github.com/matryer/is"
	"gorm.io/gorm"

	"go.pitz.tech/gorm/encryption"
)

type TypesAESGCM struct {
	Bytes  []byte `gorm:"type:bytes;serializer:aes-gcm"`
	String string `gorm:"type:bytes;serializer:aes-gcm"`

	// eventually, it would be nice to tag these, but they require database specific implementations...
	// I tried to get these to get gorm to serialize this appropriately, but theres some special handling logic
	// under the hood when using `type:bytes;`

	Int     int
	Int8    int8
	Int16   int16
	Int32   int32
	Int64   int64
	Uint    uint
	Uint8   uint8
	Uint16  uint16
	Uint32  uint32
	Uint64  uint64
	Float32 float32
	Float64 float64
}

type testAESGCMRecord struct {
	ID int `gorm:"primaryKey;autoIncrement"`

	TypesAESGCM
	Struct TypesAESGCM `gorm:"type:bytes;serializer:aes-gcm"`
}

func test(is *is.I, db *gorm.DB) {
	// setup aes key and GORM serializer

	key, err := encryption.GenerateKey()
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
