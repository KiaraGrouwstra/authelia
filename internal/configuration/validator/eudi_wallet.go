// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package validator

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
)

// ValidateEUDIWallet validates and updates the EU Digital Identity Wallet configuration.
func ValidateEUDIWallet(config *schema.Configuration, validator *schema.StructValidator) {
	if !config.EUDIWallet.Enable {
		return
	}

	validateEUDIWalletAutheliaURL(config, validator)
	validateEUDIWalletFlows(&config.EUDIWallet, validator)

	switch {
	case config.EUDIWallet.Lifetime == 0:
		config.EUDIWallet.Lifetime = schema.DefaultEUDIWalletConfiguration.Lifetime
	case config.EUDIWallet.Lifetime < 0 || config.EUDIWallet.Lifetime > schema.EUDIWalletMaximumLifetime:
		validator.Push(fmt.Errorf(errFmtEUDIWalletLifetime, schema.EUDIWalletMaximumLifetime, config.EUDIWallet.Lifetime))
	}

	validateEUDIWalletKey(&config.EUDIWallet, validator)
	validateEUDIWalletTrust(&config.EUDIWallet, validator)

	if len(config.EUDIWallet.VCTValues) == 0 {
		config.EUDIWallet.VCTValues = schema.DefaultEUDIWalletConfiguration.VCTValues
	}

	if config.EUDIWallet.MdocDocType == "" {
		config.EUDIWallet.MdocDocType = schema.DefaultEUDIWalletConfiguration.MdocDocType
	}
}

func validateEUDIWalletAutheliaURL(config *schema.Configuration, validator *schema.StructValidator) {
	autheliaURL := config.EUDIWallet.AutheliaURL

	if autheliaURL == nil {
		validator.Push(fmt.Errorf(errFmtEUDIWalletOptionRequired, "authelia_url"))

		return
	}

	if autheliaURL.Scheme != schemeHTTPS {
		validator.Push(fmt.Errorf(errFmtEUDIWalletAutheliaURLScheme, autheliaURL.Scheme))

		return
	}

	for _, cookie := range config.Session.Cookies {
		if cookie.AutheliaURL != nil && strings.TrimSuffix(cookie.AutheliaURL.String(), "/") == strings.TrimSuffix(autheliaURL.String(), "/") {
			return
		}
	}

	validator.Push(fmt.Errorf(errFmtEUDIWalletAutheliaURLCookie, autheliaURL))
}

func validateEUDIWalletFlows(config *schema.EUDIWallet, validator *schema.StructValidator) {
	if len(config.Flows) == 0 {
		config.Flows = schema.DefaultEUDIWalletConfiguration.Flows

		return
	}

	known := schema.DefaultEUDIWalletConfiguration.Flows

	for i, flow := range config.Flows {
		if !slices.Contains(known, flow) {
			validator.Push(fmt.Errorf(errFmtEUDIWalletFlowUnknown, strings.Join(known, ", "), flow))
		}

		if slices.Contains(config.Flows[:i], flow) {
			validator.Push(fmt.Errorf(errFmtEUDIWalletFlowDuplicate, flow))
		}
	}
}

func validateEUDIWalletKey(config *schema.EUDIWallet, validator *schema.StructValidator) {
	if !config.CertificateChain.HasCertificates() {
		validator.Push(fmt.Errorf(errFmtEUDIWalletOptionRequired, "certificate_chain"))
	} else {
		if err := config.CertificateChain.Validate(); err != nil {
			validator.Push(fmt.Errorf(errFmtEUDIWalletCertificateChain, err))
		}

		if leaf := config.CertificateChain.Leaf(); leaf != nil && leaf.CheckSignatureFrom(leaf) == nil {
			validator.Push(errors.New(errFmtEUDIWalletCertificateSelf))
		}
	}

	if config.PrivateKey == nil {
		validator.Push(fmt.Errorf(errFmtEUDIWalletOptionRequired, "private_key"))

		return
	}

	key, ok := config.PrivateKey.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		validator.Push(errors.New(errFmtEUDIWalletPrivateKey))

		return
	}

	if config.CertificateChain.HasCertificates() && !config.CertificateChain.EqualKey(config.PrivateKey) {
		validator.Push(errors.New(errFmtEUDIWalletPrivateKeyMatch))
	}
}

func validateEUDIWalletTrust(config *schema.EUDIWallet, validator *schema.StructValidator) {
	if len(config.TrustedIssuerRoots) == 0 {
		validator.Push(fmt.Errorf(errFmtEUDIWalletOptionRequired, "trusted_issuer_roots"))
	}

	for _, roots := range config.TrustedIssuerRoots {
		if !roots.HasCertificates() {
			validator.Push(errors.New(errFmtEUDIWalletRoots))
		}
	}

	for _, issuers := range config.CRLIssuers {
		if !issuers.HasCertificates() {
			validator.Push(errors.New(errFmtEUDIWalletCRLIssuers))
		}
	}

	switch {
	case config.DisableRevocationCheck && len(config.CRLURLs) != 0:
		validator.Push(errors.New(errFmtEUDIWalletRevocationExclusive))
	case !config.DisableRevocationCheck && len(config.CRLURLs) == 0:
		validator.Push(errors.New(errFmtEUDIWalletRevocationRequired))
	}

	for _, crl := range config.CRLURLs {
		if crl == nil || (crl.Scheme != schemeHTTP && crl.Scheme != schemeHTTPS) {
			validator.Push(fmt.Errorf(errFmtEUDIWalletCRLURL, crl))
		}
	}
}
