// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package eudiwallet

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/verifier/verifiertest"
	"github.com/stretchr/testify/require"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/storage"
)

func TestTransactionStoreContract(t *testing.T) {
	verifiertest.TestTransactionStoreContract(t, func() verifier.TransactionStore {
		config := &schema.Configuration{}
		config.Storage.EncryptionKey = "an encryption key of the required length for the test"
		config.Storage.Local = &schema.StorageLocal{Path: filepath.Join(t.TempDir(), "db.sqlite3")}

		provider, err := storage.NewSQLiteProvider(config)
		require.NoError(t, err)

		require.NoError(t, provider.SchemaMigrate(context.Background(), true, storage.SchemaLatest))

		var store *transactionStore

		store, err = newStore(config.Storage.EncryptionKey, provider)
		require.NoError(t, err)

		store.now = func() time.Time { return time.Unix(0, 0) }

		return store
	})
}
