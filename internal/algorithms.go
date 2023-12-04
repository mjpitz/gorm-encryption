// Copyright (C) 2023 Mya Pitzeruse
// SPDX-License-Identifier: MIT

package internal

import (
	"crypto/rand"
)

// Algorithm defines an encryption algorithm supported by this library.
type Algorithm struct {
	ID   byte
	Name string
}

var (
	Unknown = Algorithm{0, "unknown"}
	AES     = Algorithm{1, "aes"}
	AES_GCM = Algorithm{2, "aes-gcm"}

	AlgorithmsByName = map[string]Algorithm{
		Unknown.Name: Unknown,
		AES.Name:     AES,
		AES_GCM.Name: AES_GCM,
	}

	AlgorithmsByID = []Algorithm{
		Unknown,
		AES,
		AES_GCM,
	}
)

func GenerateKey() ([]byte, error) {
	dataKey := make([]byte, 32)

	_, err := rand.Read(dataKey)

	return dataKey, err
}
