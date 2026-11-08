// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"time"
)

// EUDIWalletTransaction is the stored form of an EU Digital Identity Wallet presentation transaction. Data is sealed.
type EUDIWalletTransaction struct {
	ID               string    `db:"id"`
	KeyID            string    `db:"key_id"`
	ResponseCodeHash string    `db:"response_code_hash"`
	Version          int64     `db:"version"`
	ExpiresAt        time.Time `db:"expires_at"`
	Data             []byte    `db:"data"`
}
