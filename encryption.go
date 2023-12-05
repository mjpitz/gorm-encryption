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
	"fmt"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/schema"

	"go.pitz.tech/gorm/encryption/aes"
	"go.pitz.tech/gorm/encryption/database"
	"go.pitz.tech/gorm/encryption/internal"
	"go.pitz.tech/gorm/encryption/internal/aesgcm"
)

// GenerateKey produces a 256bit cryptographically secure random value. This can be used as a primary key for
// encryption or as a separate data key that's encrypted in the database.
func GenerateKey() ([]byte, error) {
	return internal.GenerateKey()
}

// Config provides a simplified structure for managing encryption configuration.
type Config struct {
	Key              []byte
	CacheSize        int
	CacheDuration    time.Duration
	RotationDuration time.Duration
	Migrate          bool
	Marshaler        func(any) ([]byte, error)
	Unmarshaler      func([]byte, any) error
}

// Apply this configuration to the provided configuration.
func (c Config) Apply(cfg *Config) {
	if c.Key != nil {
		cfg.Key = c.Key
	}

	if c.CacheSize > 0 {
		cfg.CacheSize = c.CacheSize
	}

	if c.CacheDuration > 0 {
		cfg.CacheDuration = c.CacheDuration
	}

	if c.RotationDuration > 0 {
		cfg.RotationDuration = c.RotationDuration
	}

	if c.Migrate {
		cfg.Migrate = c.Migrate
	}

	if c.Marshaler != nil {
		cfg.Marshaler = c.Marshaler
	}

	if c.Unmarshaler != nil {
		cfg.Unmarshaler = c.Unmarshaler
	}
}

// OptionFunc provides a legacy stepping stone to the new configuration.
type OptionFunc func(cfg *Config)

// Apply runs the underlying function provided it's not-nil.
func (fn OptionFunc) Apply(cfg *Config) {
	if fn != nil {
		fn(cfg)
	}
}

// Option provides a common definition on how to configure optional parameters of the underlying configuration.
type Option interface {
	Apply(cfg *Config)
}

// WithKey configures the root encryption key to use.
func WithKey(key []byte) Option {
	return OptionFunc(func(cfg *Config) {
		cfg.Key = key[:]
	})
}

// WithCacheSize configures how many data keys are cached in memory before an entry is evicted.
func WithCacheSize(cacheSize int) Option {
	return OptionFunc(func(cfg *Config) {
		cfg.CacheSize = cacheSize
	})
}

// WithCacheDuration configures how long data keys are cached for before they're evicted.
func WithCacheDuration(cacheDuration time.Duration) Option {
	return OptionFunc(func(cfg *Config) {
		cfg.CacheDuration = cacheDuration
	})
}

// WithRotationDuration configures how long the underlying data encryption keys are valid for.
func WithRotationDuration(rotationDuration time.Duration) Option {
	return OptionFunc(func(cfg *Config) {
		cfg.RotationDuration = rotationDuration
	})
}

// WithMigration will automatically migrate the underlying encryption_keys schema.
func WithMigration() Option {
	return OptionFunc(func(cfg *Config) {
		cfg.Migrate = true
	})
}

// WithMarshaling provides consumers with the ability to marshal/unmarshal structures for encryption.
func WithMarshaling(marshaler func(any) ([]byte, error), unmarshaler func([]byte, any) error) Option {
	return OptionFunc(func(cfg *Config) {
		cfg.Marshaler = marshaler
		cfg.Unmarshaler = unmarshaler
	})
}

// Register enables the aes and aes-gcm serializers for the underlying Gorm database. A reference to the database is
// needed for the aes-gcm implementation to store and read keys.
func Register(db *gorm.DB, opts ...Option) error {
	cfg := &Config{
		CacheSize:        5,
		CacheDuration:    5 * time.Minute,
		RotationDuration: 10 * 24 * time.Hour,
		Marshaler:        NoMarshaler,
		Unmarshaler:      NoUnmarshaler,
	}

	for _, opt := range opts {
		opt.Apply(cfg)
	}

	schema.RegisterSerializer(internal.AES.Name, aes.New(cfg.Key))

	if cfg.Migrate {
		err := db.AutoMigrate(database.Key{})
		if err != nil {
			return err
		}
	}

	serializer, err := aesgcm.New(db, cfg.Key, cfg.CacheSize, cfg.CacheDuration, cfg.RotationDuration, cfg.Marshaler, cfg.Unmarshaler)
	if err != nil {
		return err
	}

	schema.RegisterSerializer(internal.AES_GCM.Name, serializer)

	return nil
}

// ErrMarshaling is returned when no marshaler or unmarshaler are specified for the config.
var ErrMarshaling = fmt.Errorf("marshaling not supported. you must set a marshaler and unmarshaler to enable")

// NoMarshaler is the default implementation for custom structures. It returns an error when called.
func NoMarshaler(any) ([]byte, error) {
	return nil, ErrMarshaling
}

// NoUnmarshaler is the default implementation for custom structures. It returns an error when called.
func NoUnmarshaler([]byte, any) error {
	return ErrMarshaling
}
