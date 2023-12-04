// Copyright (C) 2023 Mya Pitzeruse
// SPDX-License-Identifier: MIT

package integration_test

import (
	"testing"

	"github.com/matryer/is"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func TestPostgres(t *testing.T) {
	t.Parallel()

	is := is.New(t)

	db, err := gorm.Open(postgres.Open("postgres://gorm:gorm@127.0.0.1:5432/gormdb"))
	is.NoErr(err)

	test(is, db)
}
