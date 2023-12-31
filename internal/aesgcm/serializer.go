// Copyright (C) 2023 Mya Pitzeruse
// SPDX-License-Identifier: MIT

package aesgcm

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"reflect"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"

	"go.pitz.tech/gorm/encryption/database"
	"go.pitz.tech/gorm/encryption/internal"
)

func New(
	db *gorm.DB,
	hmac []byte,
	cacheSize int,
	cacheDuration time.Duration,
	rotationDuration time.Duration,
	marshaler func(any) ([]byte, error),
	unmarshaler func([]byte, any) error,
) (*Serializer, error) {
	hmacKey := sha256.Sum256(hmac)

	serializer := &Serializer{
		db:               db,
		hmacKey:          hmacKey[:],
		current:          make(chan *database.Key, 1),
		cache:            expirable.NewLRU[string, *database.Key](cacheSize, nil, cacheDuration),
		rotationDuration: rotationDuration,
		rotate:           time.NewTicker(rotationDuration),
		marshaler:        marshaler,
		unmarshaler:      unmarshaler,
	}

	{
		key := &database.Key{}

		err := db.
			Where("created_at > ?", time.Now().Add(-1*rotationDuration)).
			Order("created_at desc").
			Limit(1).
			Find(key).
			Error

		if err != nil || key.Fingerprint == "" {
			key, err = serializer.newKey()
			if err != nil {
				return nil, err
			}
		}

		serializer.current <- key
	}

	return serializer, nil
}

// Serializer provides a Gorm Serializer capable of encrypting and decrypting database fields using an AES+GCM
// cipher. The same encryption key can be used for multiple values in an attempt to optimize performance.
type Serializer struct {
	db *gorm.DB

	hmacKey []byte
	current chan *database.Key
	cache   *expirable.LRU[string, *database.Key]

	rotationDuration time.Duration
	rotate           *time.Ticker

	marshaler   func(any) ([]byte, error)
	unmarshaler func([]byte, any) error
}

func (s *Serializer) newKey() (*database.Key, error) {
	dataKey, err := internal.GenerateKey()
	if err != nil {
		return nil, err
	}

	hash := hmac.New(sha256.New, s.hmacKey)
	hash.Write(dataKey)

	key := &database.Key{
		Fingerprint: base64.RawURLEncoding.EncodeToString(hash.Sum(nil)),
		DataKey:     dataKey[:],
	}

	err = s.db.Create(key).Error
	if err != nil {
		return nil, err
	}

	return key, err
}

func (s *Serializer) currentKey() *database.Key {
	select {
	case <-s.rotate.C:
		current := <-s.current

		next, err := s.newKey()
		if err != nil {
			return current
		}

		s.rotate.Reset(s.rotationDuration)

		return next
	case current := <-s.current:
		return current
	}
}

// Get implements loading logic that pulls encryption keys from the database and caches them in memory to improve
// performance of decrypting field values.
func (s *Serializer) Get(fingerprint string) (*database.Key, error) {
	dataKey, ok := s.cache.Get(fingerprint)
	if !ok {
		dataKey = &database.Key{}

		err := s.db.First(dataKey, "fingerprint = ?", fingerprint).Error
		if err != nil {
			return nil, err
		}

		s.cache.Add(fingerprint, dataKey)
	}

	return dataKey, nil
}

// Scan converts on-disk, ciphertext into a plaintext in-memory field value.
func (s *Serializer) Scan(ctx context.Context, field *schema.Field, dst reflect.Value, dbValue interface{}) error {
	ciphertext, ok := dbValue.([]byte)
	if !ok {
		return fmt.Errorf("encryption only works on []byte ciphertext")
	}

	algorithm, fingerprint, ciphertext := database.ParseField(ciphertext)
	switch {
	case fingerprint == "":
		// field does not appear encrypted, treat data as plaintext
		field.ReflectValueOf(ctx, dst).SetBytes(ciphertext)

		return nil
	case algorithm != internal.AES_GCM.ID:
		return fmt.Errorf("expected %s but got: %s", internal.AES_GCM.Name, internal.AlgorithmsByID[algorithm].Name)
	}

	// get key by fingerprint

	key, err := s.Get(fingerprint)
	if err != nil {
		return err
	}

	// decrypt

	block, err := aes.NewCipher(key.DataKey)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonceSize := gcm.NonceSize()

	plaintext, err := gcm.Open(nil, ciphertext[:nonceSize], ciphertext[nonceSize:], nil)
	if err != nil {
		return err
	}

	v := field.ReflectValueOf(ctx, dst)

	if v.Kind() == reflect.Slice && v.Type().Elem().Kind() == reflect.Uint8 {
		v.SetBytes(plaintext)
	} else {
		val := reflect.New(field.FieldType)
		err = s.unmarshaler(plaintext, val.Interface())
		if err != nil {
			return err
		}

		v.Set(val.Elem())
	}

	return nil
}

// Value converts a plaintext, in-memory field value into an encrypted field value intended for storage in SQL systems.
func (s *Serializer) Value(ctx context.Context, field *schema.Field, dst reflect.Value, fieldValue interface{}) (interface{}, error) {
	var plaintext []byte
	var err error

	switch v := fieldValue.(type) {
	case []byte:
		plaintext = v
	default:
		plaintext, err = s.marshaler(v)
		if err != nil {
			return nil, err
		}
	}

	key := s.currentKey()
	defer func() { s.current <- key }()

	// encrypt

	block, err := aes.NewCipher(key.DataKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	return database.FormatField(internal.AES_GCM.ID, key.Fingerprint, ciphertext), nil
}
