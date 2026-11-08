// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"
	"go.uber.org/mock/gomock"

	"github.com/authelia/authelia/v4/internal/authentication"
	"github.com/authelia/authelia/v4/internal/mocks"
	"github.com/authelia/authelia/v4/internal/model"
	"github.com/authelia/authelia/v4/internal/session"
)

const (
	testWalletEmail   = "john@example.com"
	testWalletQueryID = "pid_sd_jwt"
)

func walletViewFor(email string) verifier.TransactionView {
	return verifier.TransactionView{
		Status: verifier.TransactionDone,
		Result: &verifier.VerifyResponseResult{Credentials: []verifier.VerifiedCredential{
			{CredentialQueryID: testWalletQueryID, Claims: map[string]any{"email": email}},
		}},
	}
}

func walletExpectAttempt(mock *mocks.MockAutheliaCtx, successful bool) {
	mock.StorageMock.EXPECT().
		AppendAuthenticationLog(gomock.Eq(mock.Ctx), gomock.Cond(func(attempt model.AuthenticationAttempt) bool {
			return attempt.Successful == successful && attempt.Type == "Wallet"
		})).
		Return(nil)
}

func walletExpectNoBan(mock *mocks.MockAutheliaCtx) {
	mock.StorageMock.EXPECT().LoadBannedIP(gomock.Eq(mock.Ctx), gomock.Any()).Return(nil, nil).AnyTimes()
	mock.StorageMock.EXPECT().LoadBannedUser(gomock.Eq(mock.Ctx), testUsername).Return(nil, nil)
}

func TestEUDIWalletFinish(t *testing.T) {
	account := &authentication.UserDetails{Username: testUsername, Emails: []string{testWalletEmail}, Groups: []string{"dev"}}

	testCases := []struct {
		name          string
		view          verifier.TransactionView
		viewErr       error
		setup         func(mock *mocks.MockAutheliaCtx)
		authenticated bool
	}{
		{
			name: "ShouldSignInWithTheEmailOfTheAccount",
			view: walletViewFor(testWalletEmail),
			setup: func(mock *mocks.MockAutheliaCtx) {
				mock.UserProviderMock.EXPECT().GetDetails(testWalletEmail).Return(account, nil)
				walletExpectNoBan(mock)
				walletExpectAttempt(mock, true)
			},
			authenticated: true,
		},
		{
			name: "ShouldSignInIgnoringTheCaseOfAnASCIIEmail",
			view: walletViewFor("John@Example.com"),
			setup: func(mock *mocks.MockAutheliaCtx) {
				mock.UserProviderMock.EXPECT().GetDetails("John@Example.com").Return(account, nil)
				walletExpectNoBan(mock)
				walletExpectAttempt(mock, true)
			},
			authenticated: true,
		},
		{
			name:    "ShouldRefuseAFailedPresentation",
			viewErr: errors.New("the presentation did not verify"),
			setup:   func(mock *mocks.MockAutheliaCtx) { walletExpectAttempt(mock, false) },
		},
		{
			name:  "ShouldRefuseAPresentationThatIsNotDone",
			view:  verifier.TransactionView{Status: verifier.TransactionClosed},
			setup: func(mock *mocks.MockAutheliaCtx) { walletExpectAttempt(mock, false) },
		},
		{
			name:  "ShouldRefuseADoneStatusWithoutAResult",
			view:  verifier.TransactionView{Status: verifier.TransactionDone},
			setup: func(mock *mocks.MockAutheliaCtx) { walletExpectAttempt(mock, false) },
		},
		{
			name: "ShouldRefuseAPresentationWithoutAnEmail",
			view: verifier.TransactionView{Status: verifier.TransactionDone, Result: &verifier.VerifyResponseResult{Credentials: []verifier.VerifiedCredential{
				{CredentialQueryID: testWalletQueryID, Claims: map[string]any{"given_name": "John"}},
			}}},
			setup: func(mock *mocks.MockAutheliaCtx) { walletExpectAttempt(mock, false) },
		},
		{
			name: "ShouldRefuseAnEmailWithoutAnAccount",
			view: walletViewFor(testWalletEmail),
			setup: func(mock *mocks.MockAutheliaCtx) {
				mock.UserProviderMock.EXPECT().GetDetails(testWalletEmail).Return(nil, authentication.ErrUserNotFound)
				walletExpectAttempt(mock, false)
			},
		},
		{
			name: "ShouldRefuseAUsernameEqualToTheEmail",
			view: walletViewFor(testWalletEmail),
			setup: func(mock *mocks.MockAutheliaCtx) {
				mock.UserProviderMock.EXPECT().GetDetails(testWalletEmail).
					Return(&authentication.UserDetails{Username: testWalletEmail, Emails: []string{"other@example.com"}}, nil)
				walletExpectAttempt(mock, false)
			},
		},
		{
			name: "ShouldRefuseABannedUser",
			view: walletViewFor(testWalletEmail),
			setup: func(mock *mocks.MockAutheliaCtx) {
				mock.UserProviderMock.EXPECT().GetDetails(testWalletEmail).Return(account, nil)
				mock.StorageMock.EXPECT().LoadBannedIP(gomock.Eq(mock.Ctx), gomock.Any()).Return(nil, nil).AnyTimes()
				mock.StorageMock.EXPECT().LoadBannedUser(gomock.Eq(mock.Ctx), testUsername).
					Return([]model.BannedUser{{Username: testUsername, Expires: sql.NullTime{Time: time.Now().Add(time.Hour), Valid: true}}}, nil)
				walletExpectAttempt(mock, false)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mock := mocks.NewMockAutheliaCtx(t)
			defer mock.Close()

			tc.setup(mock)

			userSession, err := mock.Ctx.GetSession()
			require.NoError(t, err)

			userSession.EUDIWallet = &session.EUDIWallet{Binding: "binding", TransactionID: "id", Method: "same_device"}

			eudiWalletFinish(mock.Ctx, userSession, tc.view, tc.viewErr)

			saved, err := mock.Ctx.GetSession()
			require.NoError(t, err)

			assert.Nil(t, saved.EUDIWallet)
			assert.Equal(t, tc.authenticated, saved.AuthenticationMethodRefs.EUDIWallet)
			assert.Equal(t, !tc.authenticated, saved.IsAnonymous())

			if tc.authenticated {
				assert.Equal(t, fasthttp.StatusOK, mock.Ctx.Response.StatusCode())
				assert.Equal(t, testUsername, saved.Username)
				assert.False(t, saved.AuthenticationMethodRefs.KnowledgeBasedAuthentication)
			} else {
				assert.Equal(t, fasthttp.StatusUnauthorized, mock.Ctx.Response.StatusCode())
				assert.Empty(t, saved.Username)
			}
		})
	}
}

func TestEUDIWalletPendingRefusals(t *testing.T) {
	t.Run("ShouldRefuseWithoutALogInInProgress", func(t *testing.T) {
		mock := mocks.NewMockAutheliaCtx(t)
		defer mock.Close()

		_, _, ok := eudiWalletPending(mock.Ctx)

		assert.False(t, ok)
		assert.Equal(t, fasthttp.StatusForbidden, mock.Ctx.Response.StatusCode())
	})

	t.Run("ShouldRefuseASessionThatIsSignedIn", func(t *testing.T) {
		mock := mocks.NewMockAutheliaCtx(t)
		defer mock.Close()

		userSession, err := mock.Ctx.GetSession()
		require.NoError(t, err)

		userSession.Username = testUsername
		userSession.AuthenticationMethodRefs.EUDIWallet = true
		userSession.EUDIWallet = &session.EUDIWallet{Binding: "binding", TransactionID: "id"}
		require.NoError(t, mock.Ctx.SaveSession(userSession))

		_, _, ok := eudiWalletPending(mock.Ctx)

		assert.False(t, ok)
		assert.Equal(t, fasthttp.StatusForbidden, mock.Ctx.Response.StatusCode())
	})
}
