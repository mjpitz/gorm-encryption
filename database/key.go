// Copyright (C) 2023 Mya Pitzeruse
// SPDX-License-Identifier: MIT

package database

import (
	"time"

	"gorm.io/gorm"
)

// A Key is used to secure sensitive information within the database. This approach follows how badgerdb implemented
// encryption. This allows data to be encrypted using a key that's different from the primary key provided at runtime.
// When you rotate the primary key, you simply need to re-encrypt the data keys stored within the database.
type Key struct {
	Fingerprint string         `json:"fingerprint" gorm:"column:fingerprint;type:varchar(64);primaryKey"`
	CreatedAt   time.Time      `json:"created_at" gorm:"column:created_at;index;autoCreateTime"`
	UpdatedAt   time.Time      `json:"updated_at" gorm:"column:updated_at;index;autoUpdateTime"`
	DeletedAt   gorm.DeletedAt `json:"deleted_at" gorm:"column:deleted_at;index"`
	DataKey     []byte         `json:"data_key" gorm:"column:data_key;type:bytes;serializer:aes"`
}

// TableName returns the name that should be used for the underlying table.
func (e Key) TableName() string {
	return "encryption_keys"
}
