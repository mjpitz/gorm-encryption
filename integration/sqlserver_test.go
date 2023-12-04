// Copyright (C) 2023 Mya Pitzeruse
// SPDX-License-Identifier: MIT

package integration_test

import (
	"testing"

	"github.com/matryer/is"

	"gorm.io/driver/sqlserver"
	"gorm.io/gorm"
)

func TestSQLServer(t *testing.T) {
	t.Parallel()

	is := is.New(t)

	db, err := gorm.Open(sqlserver.Open("sqlserver://sa:yourStrong(!)Password@127.0.0.1:1433?database=master"))
	is.NoErr(err)

	test(is, db)
}
