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
	DataKey     []byte         `json:"data_key" gorm:"column:data_key;type:blob;serializer:aes"`
}

// TableName returns the name that should be used for the underlying table.
func (e Key) TableName() string {
	return "encryption_keys"
}
