// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package validator

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
)

func eudiWalletTestCertificate(t *testing.T, serial int64, public crypto.PublicKey, parent *x509.Certificate, signer crypto.Signer) *x509.Certificate {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: "eudi-wallet-" + big.NewInt(serial).String()},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  parent == nil,
		BasicConstraintsValid: true,
	}

	if parent == nil {
		parent = template
	}

	der, err := x509.CreateCertificate(rand.Reader, template, parent, public, signer)
	require.NoError(t, err)

	certificate, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return certificate
}

func eudiWalletTestKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)

	return key
}

func eudiWalletTestChain(t *testing.T, certificates ...*x509.Certificate) schema.X509CertificateChain {
	t.Helper()

	return schema.NewX509CertificateChainFromCerts(certificates)
}

func newEUDIWalletTestConfiguration(t *testing.T) *schema.Configuration {
	t.Helper()

	rootKey := eudiWalletTestKey(t, elliptic.P256())
	root := eudiWalletTestCertificate(t, 1, rootKey.Public(), nil, rootKey)
	leafKey := eudiWalletTestKey(t, elliptic.P256())
	leaf := eudiWalletTestCertificate(t, 2, leafKey.Public(), root, rootKey)
	autheliaURL := &url.URL{Scheme: schemeHTTPS, Host: "auth.example.com"}

	config := &schema.Configuration{}
	config.Session.Cookies = []schema.SessionCookie{{AutheliaURL: autheliaURL}}
	config.EUDIWallet = schema.EUDIWallet{
		Enable:             true,
		AutheliaURL:        autheliaURL,
		CertificateChain:   eudiWalletTestChain(t, leaf, root),
		PrivateKey:         leafKey,
		TrustedIssuerRoots: []schema.X509CertificateChain{eudiWalletTestChain(t, root)},
		CRLURLs:            []*url.URL{{Scheme: schemeHTTPS, Host: "pki.example.com", Path: "/issuer.crl"}},
	}

	return config
}

func TestValidateEUDIWalletDisabled(t *testing.T) {
	config := &schema.Configuration{}
	validator := schema.NewStructValidator()

	ValidateEUDIWallet(config, validator)

	assert.Empty(t, validator.Errors())
	assert.Empty(t, config.EUDIWallet.Flows)
}

func TestValidateEUDIWalletDefaults(t *testing.T) {
	config := newEUDIWalletTestConfiguration(t)
	validator := schema.NewStructValidator()

	ValidateEUDIWallet(config, validator)

	assert.Empty(t, validator.Errors())
	assert.Equal(t, schema.DefaultEUDIWalletConfiguration.Flows, config.EUDIWallet.Flows)
	assert.Equal(t, schema.DefaultEUDIWalletConfiguration.Lifetime, config.EUDIWallet.Lifetime)
	assert.Equal(t, schema.DefaultEUDIWalletConfiguration.VCTValues, config.EUDIWallet.VCTValues)
	assert.Equal(t, schema.DefaultEUDIWalletConfiguration.MdocDocType, config.EUDIWallet.MdocDocType)
}

func TestValidateEUDIWalletErrors(t *testing.T) {
	testCases := []struct {
		name     string
		mutate   func(t *testing.T, config *schema.EUDIWallet)
		expected []string
	}{
		{
			"ShouldRequireAutheliaURL",
			func(_ *testing.T, config *schema.EUDIWallet) { config.AutheliaURL = nil },
			[]string{"eudi_wallet: option 'authelia_url' is required"},
		},
		{
			"ShouldRequireHTTPS",
			func(_ *testing.T, config *schema.EUDIWallet) {
				config.AutheliaURL = &url.URL{Scheme: schemeHTTP, Host: "auth.example.com"}
			},
			[]string{"eudi_wallet: option 'authelia_url' must have the scheme 'https' but it has the scheme 'http'"},
		},
		{
			"ShouldRequireAMatchingCookie",
			func(_ *testing.T, config *schema.EUDIWallet) {
				config.AutheliaURL = &url.URL{Scheme: schemeHTTPS, Host: "other.example.com"}
			},
			[]string{"eudi_wallet: option 'authelia_url' must be equal to one of the 'session' configuration 'cookies' option 'authelia_url' values but 'https://other.example.com' is not"},
		},
		{
			"ShouldRefuseUnknownAndDuplicateFlows",
			func(_ *testing.T, config *schema.EUDIWallet) {
				config.Flows = []string{"same_device", "same_device", "bad"}
			},
			[]string{
				"eudi_wallet: option 'flows' must not have the value 'same_device' more than once",
				"eudi_wallet: option 'flows' must only have the values same_device but it has the value 'bad'",
			},
		},
		{
			"ShouldRefuseALongLifetime",
			func(_ *testing.T, config *schema.EUDIWallet) { config.Lifetime = 2 * time.Hour },
			[]string{"eudi_wallet: option 'lifetime' must be more than 0 seconds and at most 1h0m0s but it is 2h0m0s"},
		},
		{
			"ShouldRequireTheCertificateChainAndKey",
			func(_ *testing.T, config *schema.EUDIWallet) {
				config.CertificateChain = schema.X509CertificateChain{}
				config.PrivateKey = nil
			},
			[]string{
				"eudi_wallet: option 'certificate_chain' is required",
				"eudi_wallet: option 'private_key' is required",
			},
		},
		{
			"ShouldRefuseASelfSignedLeaf",
			func(t *testing.T, config *schema.EUDIWallet) {
				key := eudiWalletTestKey(t, elliptic.P256())
				config.CertificateChain = eudiWalletTestChain(t, eudiWalletTestCertificate(t, 3, key.Public(), nil, key))
				config.PrivateKey = key
			},
			[]string{"eudi_wallet: option 'certificate_chain' must not have a self-signed leaf certificate"},
		},
		{
			"ShouldRefuseAnotherCurve",
			func(t *testing.T, config *schema.EUDIWallet) {
				config.PrivateKey = eudiWalletTestKey(t, elliptic.P384())
			},
			[]string{"eudi_wallet: option 'private_key' must be an ECDSA key on the P-256 curve"},
		},
		{
			"ShouldRefuseAnotherKey",
			func(t *testing.T, config *schema.EUDIWallet) {
				config.PrivateKey = eudiWalletTestKey(t, elliptic.P256())
			},
			[]string{"eudi_wallet: option 'private_key' must be the key of the leaf certificate in option 'certificate_chain'"},
		},
		{
			"ShouldRequireRoots",
			func(_ *testing.T, config *schema.EUDIWallet) { config.TrustedIssuerRoots = nil },
			[]string{"eudi_wallet: option 'trusted_issuer_roots' is required"},
		},
		{
			"ShouldRefuseEmptyRoots",
			func(_ *testing.T, config *schema.EUDIWallet) {
				config.TrustedIssuerRoots = []schema.X509CertificateChain{{}}
			},
			[]string{"eudi_wallet: option 'trusted_issuer_roots' must have at least one certificate in every value"},
		},
		{
			"ShouldRefuseEmptyCRLIssuers",
			func(_ *testing.T, config *schema.EUDIWallet) {
				config.CRLIssuers = []schema.X509CertificateChain{{}}
			},
			[]string{"eudi_wallet: option 'crl_issuers' must have at least one certificate in every value"},
		},
		{
			"ShouldRequireCRLURLs",
			func(_ *testing.T, config *schema.EUDIWallet) { config.CRLURLs = nil },
			[]string{"eudi_wallet: option 'crl_urls' is required unless option 'disable_revocation_check' is true"},
		},
		{
			"ShouldRefuseCRLURLsWithTheCheckDisabled",
			func(_ *testing.T, config *schema.EUDIWallet) { config.DisableRevocationCheck = true },
			[]string{"eudi_wallet: option 'crl_urls' must not be set when option 'disable_revocation_check' is true"},
		},
		{
			"ShouldRefuseOtherCRLSchemes",
			func(_ *testing.T, config *schema.EUDIWallet) {
				config.CRLURLs = []*url.URL{{Scheme: "ldap", Host: "pki.example.com"}}
			},
			[]string{"eudi_wallet: option 'crl_urls' must only have 'http' or 'https' URLs but it has the value 'ldap://pki.example.com'"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := newEUDIWalletTestConfiguration(t)
			tc.mutate(t, &config.EUDIWallet)

			validator := schema.NewStructValidator()
			ValidateEUDIWallet(config, validator)

			errs := make([]string, 0, len(validator.Errors()))
			for _, err := range validator.Errors() {
				errs = append(errs, err.Error())
			}

			assert.ElementsMatch(t, tc.expected, errs)
		})
	}
}
