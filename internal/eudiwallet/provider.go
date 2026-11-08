// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

// Package eudiwallet implements log-in with an EU Digital Identity Wallet over OpenID for Verifiable Presentations.
package eudiwallet

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	fapi "github.com/idfoundry/fapigo"
	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttpadaptor"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/logging"
	"github.com/authelia/authelia/v4/internal/storage"
	"github.com/authelia/authelia/v4/internal/utils"
)

const (
	// PathResponse is the path of the endpoint which receives the wallet response.
	PathResponse = "/api/firstfactor/wallet/response"

	// PathRequest is the path prefix of the endpoint which serves the request object to the wallet.
	PathRequest = "/api/firstfactor/wallet/request"

	hkdfInfoSealer = "authelia-eudi-wallet-transaction"

	maxClockSkew = 30 * time.Second

	statusCacheEntries = 1024
)

// Provider runs EU Digital Identity Wallet presentations.
type Provider struct {
	config *schema.EUDIWallet
	portal string
	origin string

	query        dcql.Query
	transactions *verifier.Transactions
	refresher    *certrevocation.Refresher
	startup      sync.Once

	requestObject fasthttp.RequestHandler
	response      fasthttp.RequestHandler
}

// NewProvider creates a Provider. The encryption key seals the stored transactions.
func NewProvider(config *schema.EUDIWallet, encryptionKey string, provider storage.Provider) (p *Provider, err error) {
	portal := strings.TrimSuffix(config.AutheliaURL.String(), "/")

	p = &Provider{
		config: config,
		portal: portal,
		origin: config.AutheliaURL.Scheme + "://" + config.AutheliaURL.Host,
	}

	if p.query, err = newQuery(config); err != nil {
		return nil, err
	}

	var (
		wallet *verifier.Verifier
		store  *transactionStore
		check  certrevocation.Checker
	)

	if wallet, err = newVerifier(config, portal); err != nil {
		return nil, err
	}

	if store, err = newStore(encryptionKey, provider); err != nil {
		return nil, err
	}

	if p.refresher, check, err = newRevocation(config); err != nil {
		return nil, err
	}

	if p.transactions, err = verifier.NewTransactions(wallet, store, transactionsConfig(config, portal, p.origin, check)); err != nil {
		return nil, fmt.Errorf("error creating the EU Digital Identity Wallet transactions: %w", err)
	}

	p.requestObject = fasthttpadaptor.NewFastHTTPHandler(p.transactions.RequestObjectHandler())
	p.response = fasthttpadaptor.NewFastHTTPHandler(p.transactions.ResponseHandler())

	return p, nil
}

func newQuery(config *schema.EUDIWallet) (query dcql.Query, err error) {
	sdjwt := dcql.SDJWTVCQuery(querySDJWT, config.VCTValues[0], dcql.KeyPath(claimSDJWTEmail))

	if sdjwt.Meta, err = json.Marshal(dcql.SDJWTVCMeta{VCTValues: config.VCTValues}); err != nil {
		return query, err
	}

	required := true

	return dcql.Query{
		Credentials: []dcql.CredentialQuery{
			sdjwt,
			dcql.MdocQuery(queryMdoc, config.MdocDocType, dcql.KeyPath(namespaceMdoc, claimMdocEmail)),
		},
		CredentialSets: []dcql.CredentialSetQuery{
			{Options: [][]string{{querySDJWT}, {queryMdoc}}, Required: &required},
		},
	}, nil
}

func newVerifier(config *schema.EUDIWallet, portal string) (wallet *verifier.Verifier, err error) {
	var responseURI fapi.URL

	if responseURI, err = fapi.ParseEndpointURL(portal + PathResponse); err != nil {
		return nil, fmt.Errorf("error parsing the EU Digital Identity Wallet response URI: %w", err)
	}

	signer, ok := config.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("the EU Digital Identity Wallet private key can not sign")
	}

	formats := verifier.MdocFormatSupport()

	for format, value := range verifier.SDJWTVCFormatSupport([]string{oid4vci.ES256}, []string{oid4vci.ES256}) {
		formats[format] = value
	}

	if wallet, err = verifier.New(verifier.Config{
		Assurance:              verifier.AssuranceProduction,
		ClientCertificate:      config.CertificateChain.Leaf(),
		ClientCertificateChain: intermediates(config.CertificateChain.Certificates()),
		ResponseURI:            responseURI,
		SigningAlg:             oid4vci.ES256,
		EncValuesSupported:     []oid4vci.JWEEnc{oid4vci.A128GCM, oid4vci.A256GCM},
		VPFormatsSupported:     formats,
	}, verifier.Dependencies{Signer: signer, Random: rand.Reader}); err != nil {
		return nil, fmt.Errorf("error creating the EU Digital Identity Wallet verifier: %w", err)
	}

	return wallet, nil
}

// intermediates returns the chain without the leaf and without a self-signed trust anchor at the end.
func intermediates(chain []*x509.Certificate) []*x509.Certificate {
	if len(chain) < 2 {
		return nil
	}

	chain = chain[1:]

	if last := chain[len(chain)-1]; bytes.Equal(last.RawSubject, last.RawIssuer) && last.CheckSignatureFrom(last) == nil {
		chain = chain[:len(chain)-1]
	}

	return chain
}

func newStore(encryptionKey string, provider storage.Provider) (store *transactionStore, err error) {
	var (
		key    []byte
		sealer verifier.TransactionSealer
	)

	if key, err = utils.DeriveCryptographicKey([]byte(encryptionKey), hkdfInfoSealer, sha256.New); err != nil {
		return nil, fmt.Errorf("error deriving the EU Digital Identity Wallet sealing key: %w", err)
	}

	if sealer, err = verifier.AESGCMSealer(key); err != nil {
		return nil, fmt.Errorf("error creating the EU Digital Identity Wallet sealer: %w", err)
	}

	return &transactionStore{provider: provider, codec: verifier.TransactionCodec{Sealer: sealer}, now: time.Now}, nil
}

func newRevocation(config *schema.EUDIWallet) (refresher *certrevocation.Refresher, check certrevocation.Checker, err error) {
	if config.DisableRevocationCheck {
		return nil, certrevocation.NoCheck{}, nil
	}

	issuers := config.CRLIssuers
	if len(issuers) == 0 {
		issuers = config.TrustedIssuerRoots
	}

	urls := make([]string, len(config.CRLURLs))

	for i, crl := range config.CRLURLs {
		urls[i] = crl.String()
	}

	if refresher, err = certrevocation.NewRefresher(certrevocation.RefresherConfig{
		URLs:    urls,
		Issuers: flatten(issuers),
		OnError: func(url string, err error) {
			logging.Logger().WithError(err).Errorf("Failed to refresh the EU Digital Identity Wallet CRL '%s'", url)
		},
	}); err != nil {
		return nil, nil, fmt.Errorf("error creating the EU Digital Identity Wallet CRL refresher: %w", err)
	}

	return refresher, refresher.Checker(), nil
}

func transactionsConfig(config *schema.EUDIWallet, portal, origin string, check certrevocation.Checker) verifier.TransactionsConfig {
	roots := x509.NewCertPool()

	for _, certificate := range flatten(config.TrustedIssuerRoots) {
		roots.AddCert(certificate)
	}

	result := verifier.TransactionsConfig{
		RequestURIBase: portal + PathRequest,
		Lifetime:       config.Lifetime,
		Verify: verifier.VerifyResponseRequest{
			IssuerKeys:          verifier.X5CIssuerKeyResolver{Roots: roots, Revocation: check},
			MdocIssuerKeys:      verifier.X5ChainIssuerKeyResolver{Roots: roots, Revocation: check},
			MaxKeyBindingAge:    config.Lifetime,
			MaxClockSkew:        maxClockSkew,
			AnyIssuerForAnyType: true,
		},
		OnRefused: func(_ context.Context, id string, err error) {
			logging.Logger().WithError(err).Warnf("Refused the EU Digital Identity Wallet response of transaction '%s'", id)
		},
		RedirectURI:        portal + "/",
		Origins:            []string{origin},
		NoStatusCheck:      config.DisableStatusCheck,
		ForgetResultOnRead: true,
	}

	if !config.DisableStatusCheck {
		result.Status = &verifier.StatusPolicy{Checker: statuslist.Checker{
			Roots:   roots,
			Options: statuslist.VerifyOptions{Revocation: check},
			Cache:   statuslist.NewCache(statuslist.CacheOptions{MaxEntries: statusCacheEntries}),
		}}
	}

	return result
}

func flatten(chains []schema.X509CertificateChain) (certificates []*x509.Certificate) {
	for _, chain := range chains {
		certificates = append(certificates, chain.Certificates()...)
	}

	return certificates
}

// StartupCheck starts the CRL refresh. An outage of a CRL does not stop the start: wallet log-in fails closed until a
// current CRL is held, and the other log-in methods still work.
func (p *Provider) StartupCheck() error {
	if p.refresher != nil {
		p.startup.Do(func() { go p.refresher.Run(context.Background()) })
	}

	return nil
}

// IsPortal returns true when the URL is the portal URL which offers the wallet log-in.
func (p *Provider) IsPortal(portal *url.URL) bool {
	return portal != nil && strings.TrimSuffix(portal.String(), "/") == p.portal
}

// Flows returns the log-in flows on offer.
func (p *Provider) Flows() []string {
	return p.config.Flows
}

// Begin starts a redirect or QR code presentation and returns the transaction ID and the link for the wallet.
func (p *Provider) Begin(ctx context.Context, binding string, sameDevice bool) (id, link string, err error) {
	var begun verifier.Begun

	if begun, err = p.transactions.Begin(ctx, p.query, binding, sameDevice); err != nil {
		return "", "", err
	}

	return begun.ID, begun.Link, nil
}

// Lookup returns the state of a transaction for the browser it is bound to.
func (p *Provider) Lookup(ctx context.Context, id, binding string) (verifier.TransactionView, error) {
	return p.transactions.Lookup(ctx, id, binding)
}

// Redeem exchanges the response code of the same-device flow for the state of the transaction.
func (p *Provider) Redeem(ctx context.Context, responseCode, binding string) (verifier.TransactionView, error) {
	return p.transactions.Redeem(ctx, responseCode, binding)
}

// Close ends a transaction.
func (p *Provider) Close(ctx context.Context, id string) error {
	return p.transactions.Close(ctx, id)
}

// ServeRequestObject serves the request object to the wallet.
func (p *Provider) ServeRequestObject(ctx *fasthttp.RequestCtx) {
	p.requestObject(ctx)
}

// ServeResponse receives the response of the wallet.
func (p *Provider) ServeResponse(ctx *fasthttp.RequestCtx) {
	p.response(ctx)
}
