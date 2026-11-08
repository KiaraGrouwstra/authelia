// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package eudiwallet

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/idfoundry/oid4vcgo/verifier"

	"github.com/authelia/authelia/v4/internal/logging"
	"github.com/authelia/authelia/v4/internal/model"
	"github.com/authelia/authelia/v4/internal/storage"
)

const (
	storeUpdateAttempts = 64
	storeUpdateMaxDelay = 20 * time.Millisecond
)

// transactionStore keeps presentation transactions in the storage provider. The codec seals every row, and each row
// has a version which makes an update atomic.
type transactionStore struct {
	provider storage.Provider
	codec    verifier.TransactionCodec
	now      func() time.Time
}

// Capabilities states that the store is durable and that updates are atomic.
func (s *transactionStore) Capabilities() verifier.StoreCapabilities {
	return verifier.StoreCapabilities{Durable: true, AtomicUpdate: true}
}

// SealsTransactions states that the store seals each transaction.
func (s *transactionStore) SealsTransactions() bool {
	return true
}

// Create saves a new transaction. The ID and the non-empty key ID must be unused.
func (s *transactionStore) Create(ctx context.Context, tx verifier.Transaction) (err error) {
	// Expired rows have no other trigger for removal, and a new transaction is the point where the table grows.
	if err = s.provider.DeleteEUDIWalletTransactionsExpired(ctx, s.now()); err != nil {
		logging.Logger().WithError(err).Warn("Failed to delete expired EU Digital Identity Wallet transactions")
	}

	if tx.KeyID != "" {
		_, err = s.provider.LoadEUDIWalletTransactionIDByKeyID(ctx, tx.KeyID)

		switch {
		case err == nil:
			return errors.New("eudi wallet transaction key ID is in use")
		case !errors.Is(err, sql.ErrNoRows):
			return err
		}
	}

	var row model.EUDIWalletTransaction

	if row, err = s.row(tx, 1); err != nil {
		return err
	}

	return s.provider.SaveEUDIWalletTransaction(ctx, row)
}

// Get returns the transaction with this ID.
func (s *transactionStore) Get(ctx context.Context, id string) (tx verifier.Transaction, err error) {
	var row *model.EUDIWalletTransaction

	if row, err = s.provider.LoadEUDIWalletTransaction(ctx, id); err != nil {
		return verifier.Transaction{}, mapNotFound(err)
	}

	return s.codec.Unmarshal(row.Data)
}

// Update applies fn to the transaction atomically. It runs fn again when another writer changed the row first.
func (s *transactionStore) Update(ctx context.Context, id string, fn func(*verifier.Transaction) error) (err error) {
	for range storeUpdateAttempts {
		var done bool

		if done, err = s.tryUpdate(ctx, id, fn); done {
			return err
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(rand.N(storeUpdateMaxDelay)): //nolint:gosec // Jitter only.
		}
	}

	return fmt.Errorf("eudi wallet transaction update did not settle: %w", err)
}

func (s *transactionStore) tryUpdate(ctx context.Context, id string, fn func(*verifier.Transaction) error) (done bool, err error) {
	var (
		current *model.EUDIWalletTransaction
		tx      verifier.Transaction
		next    model.EUDIWalletTransaction
	)

	if current, err = s.provider.LoadEUDIWalletTransaction(ctx, id); err != nil {
		if storage.IsSerializationFailure(err) {
			return false, err
		}

		return true, mapNotFound(err)
	}

	if tx, err = s.codec.Unmarshal(current.Data); err != nil {
		return true, err
	}

	if err = fn(&tx); err != nil {
		return true, err
	}

	tx.ID = id

	if next, err = s.row(tx, current.Version+1); err != nil {
		return true, err
	}

	err = s.provider.UpdateEUDIWalletTransaction(ctx, next, current.Version)

	if errors.Is(err, storage.ErrNoRowsAffected) || storage.IsSerializationFailure(err) {
		return false, err
	}

	return true, err
}

// IDByKeyID returns the ID of the transaction with this response encryption key ID.
func (s *transactionStore) IDByKeyID(ctx context.Context, kid string) (id string, err error) {
	if kid == "" {
		return "", verifier.ErrTransactionUnknown
	}

	if id, err = s.provider.LoadEUDIWalletTransactionIDByKeyID(ctx, kid); err != nil {
		return "", mapNotFound(err)
	}

	return id, nil
}

// IDByResponseCode returns the ID of the transaction with this response code hash.
func (s *transactionStore) IDByResponseCode(ctx context.Context, codeHash string) (id string, err error) {
	if codeHash == "" {
		return "", verifier.ErrTransactionUnknown
	}

	if id, err = s.provider.LoadEUDIWalletTransactionIDByResponseCodeHash(ctx, codeHash); err != nil {
		return "", mapNotFound(err)
	}

	return id, nil
}

func (s *transactionStore) row(tx verifier.Transaction, version int64) (row model.EUDIWalletTransaction, err error) {
	var data []byte

	if data, err = s.codec.Marshal(tx); err != nil {
		return row, err
	}

	expires := tx.ExpiresAt
	if tx.RetainUntil.After(expires) {
		expires = tx.RetainUntil
	}

	return model.EUDIWalletTransaction{
		ID:               tx.ID,
		KeyID:            tx.KeyID,
		ResponseCodeHash: tx.ResponseCodeHash,
		Version:          version,
		ExpiresAt:        expires.UTC(),
		Data:             data,
	}, nil
}

func mapNotFound(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return verifier.ErrTransactionUnknown
	}

	return err
}
