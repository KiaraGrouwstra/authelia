// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package eudiwallet

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/fapihttp"
	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/wallet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/storage"
)

const (
	testBinding = "binding-of-the-browser"
	testEmail   = "john@example.com"
	testOrigin  = "https://auth.example.com"
	testVCT     = "urn:eudi:pid:1"
)

// acceptingTrust stands in for the trust list of a wallet. The test does the checks of the verifier, not of the wallet.
type acceptingTrust struct{}

func (acceptingTrust) VerifyVerifierChain(chain [][]byte) (*x509.Certificate, error) {
	return x509.ParseCertificate(chain[0])
}

type testAuthority struct {
	certificate *x509.Certificate
	key         *ecdsa.PrivateKey
}

func newTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	return key
}

func newTestCertificate(t *testing.T, template *x509.Certificate, key *ecdsa.PrivateKey, parent *testAuthority) *x509.Certificate {
	t.Helper()

	signer, issuer := key, template

	if parent != nil {
		signer, issuer = parent.key, parent.certificate
	}

	raw, err := x509.CreateCertificate(rand.Reader, template, issuer, &key.PublicKey, signer)
	require.NoError(t, err)

	certificate, err := x509.ParseCertificate(raw)
	require.NoError(t, err)

	return certificate
}

func newTestAuthority(t *testing.T, name string) *testAuthority {
	t.Helper()

	key := newTestKey(t)

	return &testAuthority{key: key, certificate: newTestCertificate(t, &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, key, nil)}
}

func (a *testAuthority) issue(t *testing.T, name string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	key := newTestKey(t)

	return newTestCertificate(t, &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}, key, a), key
}

func newTestProvider(t *testing.T, trusted *testAuthority) *Provider {
	t.Helper()

	portal, err := url.Parse(testOrigin + "/")
	require.NoError(t, err)

	leaf, key := newTestAuthority(t, "verifier root").issue(t, "auth.example.com")

	config := &schema.Configuration{}
	config.Storage.EncryptionKey = "an encryption key of the required length for the test"
	config.Storage.Local = &schema.StorageLocal{Path: filepath.Join(t.TempDir(), "db.sqlite3")}

	store, err := storage.NewSQLiteProvider(config)
	require.NoError(t, err)
	require.NoError(t, store.SchemaMigrate(context.Background(), true, storage.SchemaLatest))

	provider, err := NewProvider(&schema.EUDIWallet{
		Enable:                 true,
		AutheliaURL:            portal,
		Flows:                  []string{schema.EUDIWalletFlowSameDevice, schema.EUDIWalletFlowCrossDevice, schema.EUDIWalletFlowDigitalCredentials},
		Lifetime:               time.Minute,
		CertificateChain:       schema.NewX509CertificateChainFromCerts([]*x509.Certificate{leaf}),
		PrivateKey:             key,
		TrustedIssuerRoots:     []schema.X509CertificateChain{schema.NewX509CertificateChainFromCerts([]*x509.Certificate{trusted.certificate})},
		DisableRevocationCheck: true,
		DisableStatusCheck:     true,
		VCTValues:              []string{testVCT},
		MdocDocType:            "eu.europa.ec.eudi.pid.1",
	}, config.Storage.EncryptionKey, store)
	require.NoError(t, err)

	return provider
}

func newTestCredential(t *testing.T, authority *testAuthority) wallet.HeldCredential {
	t.Helper()

	certificate, key := authority.issue(t, "issuer.example.com")
	holder := newTestKey(t)
	point, err := holder.PublicKey.Bytes()
	require.NoError(t, err)

	expires := time.Now().Add(time.Hour).Unix()

	credential, _, err := sdjwtvc.Issue(key, oid4vci.ES256, sdjwtvc.Claims{
		VCT: testVCT,
		Iss: "https://issuer.example.com",
		Exp: &expires,
		CNF: map[string]any{"jwk": map[string]any{
			"kty": "EC",
			"crv": "P-256",
			"x":   base64.RawURLEncoding.EncodeToString(point[1:33]),
			"y":   base64.RawURLEncoding.EncodeToString(point[33:]),
		}},
		Additional: map[string]any{
			claimSDJWTEmail: sdjwtvc.SD(testEmail),
			"given_name":    sdjwtvc.SD("John"),
		},
	}, sdjwtvc.IssueOptions{IssuerCertificate: certificate})
	require.NoError(t, err)

	return wallet.HeldCredential{Format: sdjwtvc.CredentialFormat, Credential: credential, HolderKey: holder, HolderKeyAlg: oid4vci.ES256}
}

func newTestRequestCtx() *fasthttp.RequestCtx {
	ctx := &fasthttp.RequestCtx{}
	ctx.Init(&fasthttp.Request{}, nil, nil)

	return ctx
}

func newTestHolder(t *testing.T) *wallet.Wallet {
	t.Helper()

	holder, err := wallet.New(
		wallet.Config{
			Assurance:       wallet.AssuranceDevelopment,
			ProofSigningAlg: oid4vci.ES256,
			VerifierTrust:   acceptingTrust{},
			Fetch:           fapihttp.Config{MaxResponseBytes: 1 << 20, RequestTimeout: time.Second, MaxRedirects: 1},
		},
		wallet.Dependencies{HTTP: http.DefaultClient, Clock: wallet.ClockFunc(time.Now), Random: rand.Reader},
	)
	require.NoError(t, err)

	return holder
}

func fetchTestRequest(t *testing.T, provider *Provider, link string) wallet.AuthorizationRequest {
	t.Helper()

	parsed, err := wallet.ParseAuthorizationRequestLink(link)
	require.NoError(t, err)

	ctx := newTestRequestCtx()
	ctx.Request.SetRequestURI(parsed.RequestURI)
	ctx.Request.Header.SetMethod(fasthttp.MethodGet)

	if parsed.RequestURIMethod == "post" {
		ctx.Request.Header.SetMethod(fasthttp.MethodPost)
		ctx.Request.Header.SetContentType("application/x-www-form-urlencoded")
	}

	provider.ServeRequestObject(ctx)
	require.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode(), string(ctx.Response.Body()))

	request, err := wallet.ParseAuthorizationRequest(wallet.ParseAuthorizationRequestParams{
		RequestObject: string(ctx.Response.Body()),
		ClientID:      parsed.ClientID,
		VerifierTrust: acceptingTrust{},
	})
	require.NoError(t, err)

	return request
}

func buildTestResponse(t *testing.T, request wallet.AuthorizationRequest, credential wallet.HeldCredential, origin string) string {
	t.Helper()

	token, err := wallet.PresentCredentials(context.Background(), wallet.PresentationRequest{
		Query:                 request.Query,
		Credentials:           []wallet.HeldCredential{credential},
		Audience:              request.ClientID,
		Origin:                origin,
		Nonce:                 request.Nonce,
		ResponseURI:           request.ResponseURI,
		ResponseEncryptionKey: request.ResponseEncryptionKey,
	})
	require.NoError(t, err)

	response, err := wallet.BuildDirectPostResponse(wallet.BuildDirectPostResponseParams{
		VPToken:         token,
		State:           request.State,
		EncryptionKey:   request.ResponseEncryptionKey,
		EncryptionKeyID: request.ResponseEncryptionKeyID,
		EncryptionEnc:   request.ResponseEncryptionEnc,
	})
	require.NoError(t, err)

	return response
}

func postTestResponse(provider *Provider, request wallet.AuthorizationRequest, response string) *fasthttp.RequestCtx {
	ctx := newTestRequestCtx()
	ctx.Request.SetRequestURI(request.ResponseURI)
	ctx.Request.Header.SetMethod(fasthttp.MethodPost)
	ctx.Request.Header.SetContentType("application/x-www-form-urlencoded")
	ctx.Request.SetBodyString(url.Values{"response": {response}}.Encode())

	provider.ServeResponse(ctx)

	return ctx
}

// presentSameDevice runs a same-device presentation and returns the response code of the redirect.
func presentSameDevice(t *testing.T, provider *Provider, authority *testAuthority) string {
	t.Helper()

	_, link, err := provider.Begin(context.Background(), testBinding, true)
	require.NoError(t, err)

	request := fetchTestRequest(t, provider, link)
	reply := postTestResponse(provider, request, buildTestResponse(t, request, newTestCredential(t, authority), ""))
	require.Equal(t, fasthttp.StatusOK, reply.Response.StatusCode(), string(reply.Response.Body()))

	var body struct {
		RedirectURI string `json:"redirect_uri"`
	}

	require.NoError(t, json.Unmarshal(reply.Response.Body(), &body))

	redirect, err := url.Parse(body.RedirectURI)
	require.NoError(t, err)

	assert.Equal(t, testOrigin+"/", redirect.Scheme+"://"+redirect.Host+redirect.Path)

	code := redirect.Query().Get("response_code")
	require.NotEmpty(t, code)

	return code
}

func TestProviderSameDevice(t *testing.T) {
	authority := newTestAuthority(t, "issuer root")
	provider := newTestProvider(t, authority)
	ctx := context.Background()

	code := presentSameDevice(t, provider, authority)

	view, err := provider.Redeem(ctx, code, testBinding)
	require.NoError(t, err)
	require.Equal(t, verifier.TransactionDone, view.Status)

	email, err := Email(view.Result)
	require.NoError(t, err)
	assert.Equal(t, testEmail, email)

	require.Len(t, view.Result.Credentials, 1)
	assert.NotContains(t, view.Result.Credentials[0].Claims, "given_name")

	_, err = provider.Redeem(ctx, code, testBinding)
	require.Error(t, err)
}

func TestProviderSameDeviceClosesOnAnotherBrowser(t *testing.T) {
	authority := newTestAuthority(t, "issuer root")
	provider := newTestProvider(t, authority)
	ctx := context.Background()

	code := presentSameDevice(t, provider, authority)

	_, err := provider.Redeem(ctx, code, "binding-of-another-browser")
	require.ErrorIs(t, err, verifier.ErrWrongBrowser)

	_, err = provider.Redeem(ctx, code, testBinding)
	require.Error(t, err)
}

func TestProviderCrossDevice(t *testing.T) {
	authority := newTestAuthority(t, "issuer root")
	provider := newTestProvider(t, authority)
	ctx := context.Background()

	id, link, err := provider.Begin(ctx, testBinding, false)
	require.NoError(t, err)

	view, err := provider.Lookup(ctx, id, testBinding)
	require.NoError(t, err)
	require.NotEqual(t, verifier.TransactionDone, view.Status)

	request := fetchTestRequest(t, provider, link)
	reply := postTestResponse(provider, request, buildTestResponse(t, request, newTestCredential(t, authority), ""))
	require.Equal(t, fasthttp.StatusOK, reply.Response.StatusCode(), string(reply.Response.Body()))
	assert.NotContains(t, string(reply.Response.Body()), "response_code")

	_, err = provider.Lookup(ctx, id, "binding-of-another-browser")
	require.Error(t, err)

	view, err = provider.Lookup(ctx, id, testBinding)
	require.NoError(t, err)
	require.Equal(t, verifier.TransactionDone, view.Status)

	email, err := Email(view.Result)
	require.NoError(t, err)
	assert.Equal(t, testEmail, email)
}

func TestProviderDigitalCredentials(t *testing.T) {
	authority := newTestAuthority(t, "issuer root")
	provider := newTestProvider(t, authority)
	ctx := context.Background()

	id, begun, err := provider.BeginDigitalCredentials(ctx, testBinding)
	require.NoError(t, err)

	data, err := json.Marshal(begun.Data)
	require.NoError(t, err)

	request, err := newTestHolder(t).ParseDCAPIRequestData(begun.Protocol, data, testOrigin)
	require.NoError(t, err)

	response, err := json.Marshal(map[string]string{"response": buildTestResponse(t, request, newTestCredential(t, authority), testOrigin)})
	require.NoError(t, err)

	view, err := provider.HandleDigitalCredentialsResponse(ctx, id, testBinding, response)
	require.NoError(t, err)
	require.Equal(t, verifier.TransactionDone, view.Status)

	email, err := Email(view.Result)
	require.NoError(t, err)
	assert.Equal(t, testEmail, email)
}

func TestProviderDigitalCredentialsRefusesAnotherOrigin(t *testing.T) {
	authority := newTestAuthority(t, "issuer root")
	provider := newTestProvider(t, authority)
	ctx := context.Background()

	id, begun, err := provider.BeginDigitalCredentials(ctx, testBinding)
	require.NoError(t, err)

	data, err := json.Marshal(begun.Data)
	require.NoError(t, err)

	// A wallet refuses this origin at parsing, so the test parses with the right one to reach the check of the verifier.
	request, err := newTestHolder(t).ParseDCAPIRequestData(begun.Protocol, data, testOrigin)
	require.NoError(t, err)

	response, err := json.Marshal(map[string]string{"response": buildTestResponse(t, request, newTestCredential(t, authority), "https://evil.example.com")})
	require.NoError(t, err)

	view, err := provider.HandleDigitalCredentialsResponse(ctx, id, testBinding, response)
	if err == nil {
		assert.NotEqual(t, verifier.TransactionDone, view.Status)
		assert.Nil(t, view.Result)
	}
}

func TestProviderRefusesAnUntrustedIssuer(t *testing.T) {
	provider := newTestProvider(t, newTestAuthority(t, "issuer root"))
	ctx := context.Background()

	id, link, err := provider.Begin(ctx, testBinding, false)
	require.NoError(t, err)

	request := fetchTestRequest(t, provider, link)
	reply := postTestResponse(provider, request, buildTestResponse(t, request, newTestCredential(t, newTestAuthority(t, "other root")), ""))
	assert.NotEqual(t, fasthttp.StatusOK, reply.Response.StatusCode())

	view, err := provider.Lookup(ctx, id, testBinding)
	if err == nil {
		assert.NotEqual(t, verifier.TransactionDone, view.Status)
		assert.Nil(t, view.Result)
	}
}
