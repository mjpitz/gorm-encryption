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
