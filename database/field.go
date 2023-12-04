// Copyright (C) 2023 Mya Pitzeruse
// SPDX-License-Identifier: MIT

package database

import (
	"bytes"
)

var (
	encryptedFieldPrefix    = []byte("ENC:")
	encryptedFieldDelimiter = []byte(",")
)

func concat(parts ...[]byte) []byte {
	length := 0
	for i := range parts {
		length += len(parts[i])
	}

	out := make([]byte, length)
	ptr := 0
	for i := range parts {
		ptr += copy(out[ptr:], parts[i])
	}

	return out
}

// FormatField takes in the various parts of the encrypted field and formats them accordingly.
func FormatField(algorithm byte, fingerprint string, ciphertext []byte) (field []byte) {
	return concat(
		encryptedFieldPrefix,
		[]byte{algorithm},
		encryptedFieldDelimiter,
		[]byte(fingerprint),
		encryptedFieldDelimiter,
		ciphertext,
	)
}

// ParseField takes in the encrypted field and separates it into its various components.
func ParseField(field []byte) (algorithm byte, fingerprint string, ciphertext []byte) {
	if !bytes.HasPrefix(field, encryptedFieldPrefix) {
		return 0, "", field
	}

	field = bytes.TrimPrefix(field, encryptedFieldPrefix)

	parts := bytes.SplitN(field, encryptedFieldDelimiter, 3)
	algorithm = parts[0][0]
	fingerprint = string(parts[1])
	ciphertext = parts[2]

	return
}
