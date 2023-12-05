// Copyright (C) 2023 Mya Pitzeruse
// SPDX-License-Identifier: MIT

package encryption_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/matryer/is"

	"go.pitz.tech/gorm/encryption"
)

func TestGenerateKey(t *testing.T) {
	i := is.New(t)

	key, err := encryption.GenerateKey()
	i.NoErr(err)
	i.Equal(32, len(key))
}

func TestConfigMerge(t *testing.T) {
	i := is.New(t)

	base := encryption.Config{}
	i.Equal(nil, base.Key)
	i.Equal(0, base.CacheSize)
	i.Equal(time.Duration(0), base.CacheDuration)
	i.Equal(time.Duration(0), base.RotationDuration)
	i.Equal(false, base.Migrate)
	i.Equal(nil, base.Marshaler)
	i.Equal(nil, base.Unmarshaler)

	key, err := encryption.GenerateKey()
	i.NoErr(err)

	encryption.Config{
		Key:              key,
		CacheSize:        100,
		CacheDuration:    time.Minute,
		RotationDuration: time.Hour,
		Migrate:          true,
		Marshaler:        json.Marshal,
		Unmarshaler:      json.Unmarshal,
	}.Apply(&base)

	i.Equal(key, base.Key)
	i.Equal(100, base.CacheSize)
	i.Equal(time.Minute, base.CacheDuration)
	i.Equal(time.Hour, base.RotationDuration)
	i.Equal(true, base.Migrate)
	i.Equal(json.Marshal, base.Marshaler)
	i.Equal(json.Unmarshal, base.Unmarshaler)
}

func TestConfigOptions(t *testing.T) {
	i := is.New(t)

	base := encryption.Config{}
	i.Equal(nil, base.Key)
	i.Equal(0, base.CacheSize)
	i.Equal(time.Duration(0), base.CacheDuration)
	i.Equal(time.Duration(0), base.RotationDuration)
	i.Equal(false, base.Migrate)
	i.Equal(nil, base.Marshaler)
	i.Equal(nil, base.Unmarshaler)

	key, err := encryption.GenerateKey()
	i.NoErr(err)

	encryption.WithKey(key).Apply(&base)
	i.Equal(key, base.Key)

	encryption.WithCacheSize(100).Apply(&base)
	i.Equal(100, base.CacheSize)

	encryption.WithCacheDuration(time.Minute).Apply(&base)
	i.Equal(time.Minute, base.CacheDuration)

	encryption.WithRotationDuration(time.Hour).Apply(&base)
	i.Equal(time.Hour, base.RotationDuration)

	encryption.WithMigration().Apply(&base)
	i.Equal(true, base.Migrate)

	encryption.WithMarshaling(json.Marshal, json.Unmarshal).Apply(&base)
	i.Equal(json.Marshal, base.Marshaler)
	i.Equal(json.Unmarshal, base.Unmarshaler)
}

func TestMarshaling(t *testing.T) {
	i := is.New(t)

	_, err := encryption.NoMarshaler(nil)
	i.Equal(encryption.ErrMarshaling, err)

	err = encryption.NoUnmarshaler(nil, nil)
	i.Equal(encryption.ErrMarshaling, err)
}
