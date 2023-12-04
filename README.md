# gorm-encryption

Easily encrypt data at rest in relational databases using drop-in Gorm Serializers.

**Ok, but _how?_**

This library draws inspiration from how SOPS handles encrypting fields in a simple configuration file as well as how
BadgerDB implements its encryption key management behind the scenes. When a `[]byte` field is encrypted using this
library, it's formatted as follows: `ENC:algorithm,fingerprint,ciphertext`. The `algorithm` is a single byte
representing `aes` (1) or `aes-gcm` (2). This indicates which serializer was used when storing the fields in the
database. `fingerprint` identifies which encryption key was used to encrypt the field. This can allow multiple to be
chained together in order to handle multiple keys or even migrations (TBD). Finally, the `ciphertext` block is the
encrypted value.

The `aes` serializer uses direct key encryption. It is recommended that the `aes` serializer not be used to encrypt
values that may be repeated. This is because the `aes` serializer does not factor a unique seed in with each entry.
Instead, it's expected that the values being encrypted are unique (for example, other encryption keys).

The `aes-gcm` serializer uses intermediary keys that are stored in the `encryption_keys` table to encrypt data across
the entire database. Unlike the `aes` serializer, the `aes-gcm` serializers is safe to use on values that may be
repeated. The key itself is encrypted using the `aes` serializer, making it easy to rotate the root key without needing
to read, decrypt, and re-encrypt every field in the database. This makes rotations quick and strongly protects the core
encryption keys from attackers.

## Support

| Driver                     | Supported | Notes                                              |
|----------------------------|-----------|----------------------------------------------------|
| github.com/glebarez/sqlite | ✅         | Support since day one.                             |
| gorm.io/driver/postgres    | ✅         | -                                                  |
| gorm.io/driver/mysql       | ❌         | https://github.com/mjpitz/gorm-encryption/issues/3 |
| gorm.io/driver/sqlserver   | ✅         | -                                                  |

## Usage

```shell
go get go.pitz.tech/gorm/encryption
```

### Tagging fields for encryption

Gorm uses tags to communicate which serializer should be used when reading and writing the field to the database. This
library only supports using the `aes` and `aes-gcm` serializers on `[]byte` fields.

```go
package main

type Model struct {
	UniqueValue    []byte `gorm:"...;serializer:aes"`
	NonUniqueValue []byte `gorm:"...;serializer:aes-gcm"`
}
```

**A few notes...**

First, when using fixed size `[]byte` fields, you'll need to consider the length added by the additional metadata of the
encrypted fields. The equations below roughly communicate how much additional length will be needed.

* `aes = data length + 50`
* `aes-gcm = data length + 62`

The various lengths for the additional metadata are as follows:

* prefix = 4 bytes
* algorithm = 1 byte
* separator = 1 byte
* fingerprint = 43 bytes
* separator = 1 byte
* data = `x` bytes (aes) | `x` + 12 bytes (aes-gcm)

Second, you need to be mindful of how indexes are used in conjunction with encrypted fields. For example, if you're
encrypting an `email_address` using `aes-gcm`, then you can't use a `unique` index on that field. You can however use a
unique index on a semi-representative field such as an `email_hash`. Which can be in plaintext in the database. While
you could encrypt your `email_address` using the `aes` serializer, the field would require explicit rotation.

### With database migrations

```go
package main

import (
	"go.pitz.tech/gorm/encryption"
	"gorm.io/gorm"
)

func migrate(encryptionKey []byte) error {
	var dialector gorm.Dialector

	db, err := gorm.Open(dialector, nil)
	if err != nil {
		return err
	}

	err = encryption.Register(db, encryption.WithKey(encryptionKey), encryption.WithMigration())
	if err != nil {
		return err
	}

	return db.AutoMigrate(
		// your application models...
	)
}
```

### Without database migrations

```go
package main

import (
	"go.pitz.tech/gorm/encryption"
	"gorm.io/gorm"
)

func run(encryptionKey []byte) error {
	var dialector gorm.Dialector

	db, err := gorm.Open(dialector, nil)
	if err != nil {
		return err
	}

	err = encryption.Register(db, encryption.WithKey(encryptionKey))
	if err != nil {
		return err
	}

	// your business logic

	return nil
}
```

### Custom AES serializer

```go
package main

import (
	"go.pitz.tech/gorm/encryption"
	"go.pitz.tech/gorm/encryption/aes"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

func run(customKey []byte) error {
	schema.RegisterSerializer("custom-aes", aes.New(customKey))
	// now you have `serializer:custom-aes`

	var dialector gorm.Dialector

	db, err := gorm.Open(dialector, nil)
	if err != nil {
		return err
	}

	// your business logic

	return nil
}
```

## Rotating keys

The code below hasn't been tested, but conveys the basic idea on how to rotate the primary encryption key.

```go
package main

import (
	"database/sql"

	"go.pitz.tech/gorm/encryption"
	"go.pitz.tech/gorm/encryption/database"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

func rotate(oldKey, newKey []byte) error {
	var dialector gorm.Dialector

	db, err := gorm.Open(dialector, nil)
	if err != nil {
		return err
	}

	// to do this in batches, you simply need to paginate the following block until you iterate through the entire table

	err = encryption.Register(db, encryption.WithKey(oldKey))
	if err != nil {
		return err
	}

	allKeys := make([]database.Key, 0)
	err = db.Find(&allKeys).Error
	if err != nil {
		return err
	}

	err = encryption.Register(db, encryption.WithKey(newKey))
	if err != nil {
		return err
	}

	return db.Transaction(func(txn *gorm.DB) error {
		for _, key := range allKeys {
			err := txn.Save(key).Error
			if err != nil {
				return err
			}
		}

		return nil
	})
}
```

## License

`MIT`. See [LICENSE](LICENSE) for more details.
