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
