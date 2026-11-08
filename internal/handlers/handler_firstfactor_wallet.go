// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"errors"
	"slices"

	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/valyala/fasthttp"

	"github.com/authelia/authelia/v4/internal/authentication"
	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/eudiwallet"
	"github.com/authelia/authelia/v4/internal/middlewares"
	"github.com/authelia/authelia/v4/internal/random"
	"github.com/authelia/authelia/v4/internal/regulation"
	"github.com/authelia/authelia/v4/internal/session"
)

const eudiWalletBindingLength = 64

type bodyWalletBeginRequest struct {
	Method         string `json:"method"`
	TargetURL      string `json:"targetURL"`
	RequestMethod  string `json:"requestMethod"`
	KeepMeLoggedIn *bool  `json:"keepMeLoggedIn"`
	FlowID         string `json:"flowID"`
	Flow           string `json:"flow"`
	SubFlow        string `json:"subflow"`
	UserCode       string `json:"userCode"`
}

type bodyWalletBeginResponse struct {
	Link string `json:"link,omitempty"`
}

type bodyWalletRedeemRequest struct {
	ResponseCode string `json:"responseCode"`
}

type bodyWalletStatusResponse struct {
	Pending bool `json:"pending"`
}

// FirstFactorWalletBeginPOST starts a wallet log-in for an anonymous session.
func FirstFactorWalletBeginPOST(ctx *middlewares.AutheliaCtx) {
	var (
		body        bodyWalletBeginRequest
		userSession session.UserSession
		err         error
	)

	if err = ctx.ParseBody(&body); err != nil {
		ctx.Logger.WithError(err).Error("Failed to parse the wallet log-in request")
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetJSONError(messageOperationFailed)

		return
	}

	provider := ctx.Providers.EUDIWallet

	if !slices.Contains(provider.Flows(), body.Method) {
		ctx.Logger.Errorf("The wallet log-in method '%s' is not enabled", body.Method)
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetJSONError(messageOperationFailed)

		return
	}

	if userSession, err = ctx.GetSession(); err != nil {
		ctx.Logger.WithError(err).Error("Failed to get the session for a wallet log-in")
		eudiWalletForbidden(ctx)

		return
	}

	if !userSession.IsAnonymous() {
		ctx.Logger.WithError(errUserIsAlreadyAuthenticated).Error("Failed to start a wallet log-in")
		eudiWalletForbidden(ctx)

		return
	}

	issuer, err := ctx.IssuerURL()
	if err != nil || !provider.IsPortal(issuer) {
		ctx.Logger.WithError(err).Errorf("Wallet log-in is not offered on the portal '%s'", issuer)
		eudiWalletForbidden(ctx)

		return
	}

	var binding string

	if binding, err = ctx.GetRandom().StringCustomErr(eudiWalletBindingLength, random.CharSetAlphaNumeric); err != nil {
		ctx.Logger.WithError(err).Error("Failed to generate the wallet log-in browser binding")
		eudiWalletForbidden(ctx)

		return
	}

	if userSession.EUDIWallet != nil {
		if err = provider.Close(ctx, userSession.EUDIWallet.TransactionID); err != nil {
			ctx.Logger.WithError(err).Debug("Failed to close the previous wallet log-in")
		}
	}

	var (
		id       string
		response bodyWalletBeginResponse
	)

	id, response.Link, err = provider.Begin(ctx, binding, body.Method == schema.EUDIWalletFlowSameDevice)
	if err != nil {
		ctx.Logger.WithError(err).Error("Failed to start a wallet presentation")
		eudiWalletForbidden(ctx)

		return
	}

	userSession.EUDIWallet = &session.EUDIWallet{
		Binding:        binding,
		TransactionID:  id,
		Method:         body.Method,
		TargetURL:      body.TargetURL,
		RequestMethod:  body.RequestMethod,
		KeepMeLoggedIn: body.KeepMeLoggedIn != nil && *body.KeepMeLoggedIn,
		FlowID:         body.FlowID,
		Flow:           body.Flow,
		SubFlow:        body.SubFlow,
		UserCode:       body.UserCode,
	}

	if err = ctx.SaveSession(userSession); err != nil {
		ctx.Logger.WithError(err).Errorf(logFmtErrSessionSave, "wallet log-in", regulation.AuthTypeWallet, logFmtActionAuthentication, userSession.Username)
		eudiWalletForbidden(ctx)

		return
	}

	if err = ctx.SetJSONBody(response); err != nil {
		ctx.Logger.WithError(err).Error("Failed to write the wallet log-in response")
	}
}

// FirstFactorWalletStatusPOST reports whether the wallet answered a cross-device log-in, and finishes the log-in when
// it did.
func FirstFactorWalletStatusPOST(ctx *middlewares.AutheliaCtx) {
	userSession, wallet, ok := eudiWalletPending(ctx)
	if !ok {
		return
	}

	view, err := ctx.Providers.EUDIWallet.Lookup(ctx, wallet.TransactionID, wallet.Binding)
	if err == nil && (view.Status == verifier.TransactionPending || view.Status == verifier.TransactionAwaitingRedirect) {
		if err = ctx.SetJSONBody(bodyWalletStatusResponse{Pending: true}); err != nil {
			ctx.Logger.WithError(err).Error("Failed to write the wallet log-in status")
		}

		return
	}

	eudiWalletFinish(ctx, userSession, view, err)
}

// FirstFactorWalletRedeemPOST finishes a same-device log-in with the response code from the wallet redirect.
func FirstFactorWalletRedeemPOST(ctx *middlewares.AutheliaCtx) {
	var body bodyWalletRedeemRequest

	if err := ctx.ParseBody(&body); err != nil {
		ctx.Logger.WithError(err).Error("Failed to parse the wallet response code")
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetJSONError(messageOperationFailed)

		return
	}

	userSession, wallet, ok := eudiWalletPending(ctx)
	if !ok {
		return
	}

	view, err := ctx.Providers.EUDIWallet.Redeem(ctx, body.ResponseCode, wallet.Binding)

	eudiWalletFinish(ctx, userSession, view, err)
}

// FirstFactorWalletRequestObject serves the request object to the wallet. The wallet has no session.
func FirstFactorWalletRequestObject(ctx *middlewares.AutheliaCtx) {
	ctx.Providers.EUDIWallet.ServeRequestObject(ctx.RequestCtx)
}

// FirstFactorWalletResponsePOST receives the response of the wallet. The wallet has no session.
func FirstFactorWalletResponsePOST(ctx *middlewares.AutheliaCtx) {
	ctx.Providers.EUDIWallet.ServeResponse(ctx.RequestCtx)
}

func eudiWalletForbidden(ctx *middlewares.AutheliaCtx) {
	ctx.SetStatusCode(fasthttp.StatusForbidden)
	ctx.SetJSONError(messageAuthenticationFailed)
}

func eudiWalletUnauthorized(ctx *middlewares.AutheliaCtx) {
	ctx.SetStatusCode(fasthttp.StatusUnauthorized)
	ctx.SetJSONError(messageAuthenticationFailed)
}

// eudiWalletPending returns the anonymous session with its wallet log-in in progress.
func eudiWalletPending(ctx *middlewares.AutheliaCtx) (userSession session.UserSession, wallet *session.EUDIWallet, ok bool) {
	var err error

	if userSession, err = ctx.GetSession(); err != nil {
		ctx.Logger.WithError(err).Error("Failed to get the session for a wallet log-in")
		eudiWalletForbidden(ctx)

		return userSession, nil, false
	}

	if !userSession.IsAnonymous() {
		ctx.Logger.WithError(errUserIsAlreadyAuthenticated).Error("Failed to continue a wallet log-in")
		eudiWalletForbidden(ctx)

		return userSession, nil, false
	}

	if userSession.EUDIWallet == nil {
		ctx.Logger.Error("Failed to continue a wallet log-in: the session has no wallet log-in in progress")
		eudiWalletForbidden(ctx)

		return userSession, nil, false
	}

	return userSession, userSession.EUDIWallet, true
}

// eudiWalletAccount finds the account of a verified presentation. It marks the failed attempt and writes the response
// when no account matches.
func eudiWalletAccount(ctx *middlewares.AutheliaCtx, view verifier.TransactionView) (*authentication.UserDetails, bool) {
	var (
		email   string
		details *authentication.UserDetails
		err     error
	)

	if email, err = eudiwallet.Email(view.Result); err != nil {
		ctx.Logger.WithError(err).Error("Failed to read the email address of the wallet presentation")
		doMarkAuthenticationAttempt(ctx, false, regulation.NewBan(regulation.BanTypeNone, "", nil), regulation.AuthTypeWallet, nil)
		eudiWalletUnauthorized(ctx)

		return nil, false
	}

	if details, err = ctx.Providers.UserProvider.GetDetails(email); err != nil {
		ctx.Logger.WithError(err).Error("Failed to find the account of the wallet presentation")
		doMarkAuthenticationAttempt(ctx, false, regulation.NewBan(regulation.BanTypeNone, "", nil), regulation.AuthTypeWallet, nil)
		eudiWalletUnauthorized(ctx)

		return nil, false
	}

	// The lookup also matches usernames, so a username equal to the presented address must not sign in.
	if !eudiwallet.EmailMatches(details.Emails, email) {
		ctx.Logger.WithError(errors.New("the presented email address is not an email address of the account")).
			Errorf("Failed to sign in user '%s' with a wallet", details.Username)
		doMarkAuthenticationAttempt(ctx, false, regulation.NewBan(regulation.BanTypeNone, details.Username, nil), regulation.AuthTypeWallet, nil)
		eudiWalletUnauthorized(ctx)

		return nil, false
	}

	return details, true
}

// eudiWalletFinish signs the session in after a verified presentation. The wallet log-in in progress ends here in every
// case, so a code or a transaction is never tried twice for one session.
func eudiWalletFinish(ctx *middlewares.AutheliaCtx, userSession session.UserSession, view verifier.TransactionView, viewErr error) {
	wallet := userSession.EUDIWallet
	userSession.EUDIWallet = nil

	var err error

	defer func() {
		if err := ctx.SaveSession(userSession); err != nil {
			ctx.Logger.WithError(err).Errorf(logFmtErrSessionSave, "wallet log-in", regulation.AuthTypeWallet, logFmtActionAuthentication, userSession.Username)
		}
	}()

	if viewErr != nil || view.Status != verifier.TransactionDone || view.Result == nil {
		ctx.Logger.WithError(viewErr).Errorf("The wallet presentation did not complete and has the status '%v'", view.Status)
		doMarkAuthenticationAttempt(ctx, false, regulation.NewBan(regulation.BanTypeNone, "", nil), regulation.AuthTypeWallet, nil)
		eudiWalletUnauthorized(ctx)

		return
	}

	details, ok := eudiWalletAccount(ctx, view)
	if !ok {
		return
	}

	if ban, _, expires, err := ctx.Providers.Regulator.BanCheck(ctx, details.Username); err != nil {
		eudiWalletUnauthorized(ctx)

		if errors.Is(err, regulation.ErrUserIsBanned) {
			doMarkAuthenticationAttempt(ctx, false, regulation.NewBan(ban, details.Username, expires), regulation.AuthTypeWallet, nil)
		} else {
			ctx.Logger.WithError(err).Errorf(logFmtErrRegulationFail, regulation.AuthTypeWallet, details.Username)
		}

		return
	}

	if err = ctx.RegenerateSession(); err != nil {
		ctx.Logger.WithError(err).Errorf(logFmtErrSessionRegenerate, regulation.AuthTypeWallet, details.Username)
		doMarkAuthenticationAttempt(ctx, false, regulation.NewBan(regulation.BanTypeNone, details.Username, nil), regulation.AuthTypeWallet, nil)
		eudiWalletForbidden(ctx)

		return
	}

	doMarkAuthenticationAttempt(ctx, true, regulation.NewBan(regulation.BanTypeNone, details.Username, nil), regulation.AuthTypeWallet, nil)

	if ctx.Configuration.AuthenticationBackend.RefreshInterval.Update() {
		userSession.RefreshTTL = ctx.GetClock().Now().Add(ctx.Configuration.AuthenticationBackend.RefreshInterval.Value())
	}

	sessionProvider, err := ctx.GetSessionProvider()
	if err != nil {
		ctx.Logger.WithError(err).Error("Failed to get the session provider for a wallet log-in")
		eudiWalletForbidden(ctx)

		return
	}

	keepMeLoggedIn := !sessionProvider.Config.DisableRememberMe && wallet.KeepMeLoggedIn

	if keepMeLoggedIn {
		if err = sessionProvider.UpdateExpiration(ctx.RequestCtx, sessionProvider.Config.RememberMe); err != nil {
			ctx.Logger.WithError(err).Errorf(logFmtErrSessionSave, "updated expiration", regulation.AuthTypeWallet, logFmtActionAuthentication, details.Username)
			eudiWalletForbidden(ctx)

			return
		}
	}

	userSession.SetOneFactorEUDIWallet(ctx.GetClock().Now(), details, keepMeLoggedIn)

	if len(wallet.Flow) > 0 {
		handleFlowResponse(ctx, &userSession, wallet.FlowID, wallet.Flow, wallet.SubFlow, wallet.UserCode)
	} else {
		HandlePasskeyResponse(ctx, wallet.TargetURL, wallet.RequestMethod, userSession.Username, userSession.Groups, false)
	}
}
