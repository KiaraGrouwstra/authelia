// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"net/url"
	"time"
)

const (
	// EUDIWalletFlowSameDevice is the flow where the wallet is on the device of the browser.
	EUDIWalletFlowSameDevice = "same_device"

	// EUDIWalletMaximumLifetime is the longest permitted lifetime of a presentation transaction.
	EUDIWalletMaximumLifetime = time.Hour
)

// EUDIWallet represents the EU Digital Identity Wallet log-in configuration.
type EUDIWallet struct {
	Enable      bool     `koanf:"enable" yaml:"enable" toml:"enable" json:"enable" jsonschema:"default=false,title=Enable" jsonschema_description:"Enables log-in with an EU Digital Identity Wallet as a first factor."`
	AutheliaURL *url.URL `koanf:"authelia_url" yaml:"authelia_url,omitempty" toml:"authelia_url,omitempty" json:"authelia_url,omitempty" jsonschema:"format=uri,title=Authelia URL" jsonschema_description:"The Authelia portal URL which offers the wallet log-in. It must be equal to the authelia_url of one session cookie."`

	Flows    []string      `koanf:"flows" yaml:"flows,omitempty" toml:"flows,omitempty" json:"flows,omitempty" jsonschema:"enum=same_device,title=Flows" jsonschema_description:"The log-in flows to offer."`
	Lifetime time.Duration `koanf:"lifetime" yaml:"lifetime,omitempty" toml:"lifetime,omitempty" json:"lifetime,omitempty" jsonschema:"default=5 minutes,title=Lifetime" jsonschema_description:"The lifetime of a presentation transaction."`

	CertificateChain X509CertificateChain    `koanf:"certificate_chain" yaml:"certificate_chain,omitempty" toml:"certificate_chain,omitempty" json:"certificate_chain,omitempty" jsonschema:"title=Certificate Chain" jsonschema_description:"The Relying Party access certificate chain which signs presentation requests."`
	PrivateKey       CryptographicPrivateKey `koanf:"private_key" yaml:"private_key,omitempty" toml:"private_key,omitempty" json:"private_key,omitempty" jsonschema:"title=Private Key" jsonschema_description:"The P-256 private key of the leaf certificate in the certificate chain."`

	TrustedIssuerRoots []X509CertificateChain `koanf:"trusted_issuer_roots" yaml:"trusted_issuer_roots,omitempty" toml:"trusted_issuer_roots,omitempty" json:"trusted_issuer_roots,omitempty" jsonschema:"title=Trusted Issuer Roots" jsonschema_description:"The root certificates of the Person Identification Data providers to trust."`

	CRLIssuers             []X509CertificateChain `koanf:"crl_issuers" yaml:"crl_issuers,omitempty" toml:"crl_issuers,omitempty" json:"crl_issuers,omitempty" jsonschema:"title=CRL Issuers" jsonschema_description:"The certificates which may sign the certificate revocation lists. The default is the trusted issuer roots."`
	CRLURLs                []*url.URL             `koanf:"crl_urls" yaml:"crl_urls,omitempty" toml:"crl_urls,omitempty" json:"crl_urls,omitempty" jsonschema:"title=CRL URLs" jsonschema_description:"The certificate revocation lists to check the certificates of the issuers against."`
	DisableRevocationCheck bool                   `koanf:"disable_revocation_check" yaml:"disable_revocation_check" toml:"disable_revocation_check" json:"disable_revocation_check" jsonschema:"default=false,title=Disable Revocation Check" jsonschema_description:"Disables the certificate revocation check of the issuers."`
	DisableStatusCheck     bool                   `koanf:"disable_status_check" yaml:"disable_status_check" toml:"disable_status_check" json:"disable_status_check" jsonschema:"default=false,title=Disable Status Check" jsonschema_description:"Disables the check of the credential status list."`

	VCTValues   []string `koanf:"vct_values" yaml:"vct_values,omitempty" toml:"vct_values,omitempty" json:"vct_values,omitempty" jsonschema:"default=urn:eudi:pid:1,title=VCT Values" jsonschema_description:"The SD-JWT VC types to accept as Person Identification Data."`
	MdocDocType string   `koanf:"mdoc_doc_type" yaml:"mdoc_doc_type,omitempty" toml:"mdoc_doc_type,omitempty" json:"mdoc_doc_type,omitempty" jsonschema:"default=eu.europa.ec.eudi.pid.1,title=mdoc Document Type" jsonschema_description:"The ISO mdoc document type to accept as Person Identification Data."`
}

// DefaultEUDIWalletConfiguration describes the default values for the EU Digital Identity Wallet configuration.
var DefaultEUDIWalletConfiguration = EUDIWallet{
	Flows:       []string{EUDIWalletFlowSameDevice},
	Lifetime:    5 * time.Minute,
	VCTValues:   []string{"urn:eudi:pid:1"},
	MdocDocType: "eu.europa.ec.eudi.pid.1",
}
