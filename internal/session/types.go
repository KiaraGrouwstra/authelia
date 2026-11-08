// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"net"
	"time"

	"github.com/fasthttp/session/v2"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/authelia/authelia/v4/internal/authorization"
)

// ProviderConfig is the configuration used to create the session provider.
type ProviderConfig struct {
	config       session.Config
	providerName string
}

// UserSession is the structure representing the session of a user.
type UserSession struct {
	CookieDomain string

	Username    string
	DisplayName string
	// TODO(c.michaud): move groups out of the session.
	Groups []string
	Emails []string

	KeepMeLoggedIn bool
	LastActivity   int64

	FirstFactorAuthnTimestamp  int64
	SecondFactorAuthnTimestamp int64

	AuthenticationMethodRefs authorization.AuthenticationMethodsReferences

	// WebAuthn holds the session registration data for this session.
	WebAuthn *WebAuthn
	TOTP     *TOTP

	// EUDIWallet holds the EU Digital Identity Wallet log-in in progress for this session.
	EUDIWallet *EUDIWallet

	// This boolean is set to true after identity verification and checked
	// while doing the query actually updating the password.
	PasswordResetUsername *string

	RefreshTTL time.Time

	Elevations Elevations
}

// TOTP holds the TOTP registration session data.
type TOTP struct {
	Issuer    string
	Algorithm string
	Digits    uint32
	Period    uint
	Secret    string
	Expires   time.Time
}

// WebAuthn holds the standard WebAuthn session data plus some extra.
type WebAuthn struct {
	*webauthn.SessionData
	Description string `json:"description"`
}

// Identity of the user who is being verified.
type Identity struct {
	Username    string
	Email       string
	DisplayName string
}

// Elevations describes various session elevations.
type Elevations struct {
	User *Elevation
}

// Elevation is an individual elevation.
type Elevation struct {
	ID       int
	RemoteIP net.IP
	Expires  time.Time
}

// EUDIWallet holds the state of an EU Digital Identity Wallet log-in in progress. The same-device flow leaves the page
// and comes back, so the session keeps what the page would otherwise send when the log-in finishes.
type EUDIWallet struct {
	// Binding is the random value that ties the presentation transaction to this browser session.
	Binding string

	// TransactionID identifies the presentation transaction.
	TransactionID string

	// Method is the log-in method: same_device, cross_device, or digital_credentials.
	Method string

	TargetURL      string
	RequestMethod  string
	KeepMeLoggedIn bool
	FlowID         string
	Flow           string
	SubFlow        string
	UserCode       string
}
