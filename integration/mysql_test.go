// Copyright (C) 2023 Mya Pitzeruse
// SPDX-License-Identifier: MIT

package integration_test

import (
	"testing"

	"github.com/matryer/is"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

func TestMySQL(t *testing.T) {
	t.Parallel()
	t.SkipNow()

	is := is.New(t)

	db, err := gorm.Open(mysql.Open("gorm:gorm@tcp(127.0.0.1:3306)/gormdb"))
	is.NoErr(err)

	test(is, db)
}
