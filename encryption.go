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

package encryption

import (
	"time"

	"go.pitz.tech/gorm/encryption/aes"
	"go.pitz.tech/gorm/encryption/database"
	"go.pitz.tech/gorm/encryption/internal"
	"go.pitz.tech/gorm/encryption/internal/aesgcm"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

// GenerateKey produces a 256bit cryptographically secure random value. This can be used as a primary key for
// encryption or as a separate data key that's encrypted in the database.
func GenerateKey() ([]byte, error) {
	return internal.GenerateKey()
}

type config struct {
	key              []byte
	rotationDuration time.Duration
	migrate          bool
}

// Option provides a common definition on how to configure optional parameters of the underlying configuration.
type Option func(cfg *config)

// WithKey configures the root encryption key to use.
func WithKey(key []byte) Option {
	return func(cfg *config) {
		cfg.key = key[:]
	}
}

// WithRotationDuration configures how long the underlying data encryption keys are valid for.
func WithRotationDuration(rotationDuration time.Duration) Option {
	return func(cfg *config) {
		cfg.rotationDuration = rotationDuration
	}
}

// WithMigration will automatically migrate the underlying encryption_keys schema.
func WithMigration() Option {
	return func(cfg *config) {
		cfg.migrate = true
	}
}

// Register enables the aes and aes-gcm serializers for the underlying Gorm database. A reference to the database is
// needed for the aes-gcm implementation to store and read keys.
func Register(db *gorm.DB, opts ...Option) error {
	cfg := &config{
		rotationDuration: 10 * 24 * time.Hour,
	}

	for _, opt := range opts {
		opt(cfg)
	}

	schema.RegisterSerializer(internal.AES.Name, aes.New(cfg.key))

	if cfg.migrate {
		err := db.AutoMigrate(database.Key{})
		if err != nil {
			return err
		}
	}

	serializer, err := aesgcm.New(db, cfg.key, cfg.rotationDuration)
	if err != nil {
		return err
	}

	schema.RegisterSerializer(internal.AES_GCM.Name, serializer)

	return nil
}