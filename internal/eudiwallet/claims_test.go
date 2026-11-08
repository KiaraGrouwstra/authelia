// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package eudiwallet

import (
	"testing"

	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/stretchr/testify/assert"
)

func credential(id string, claims map[string]any) verifier.VerifiedCredential {
	return verifier.VerifiedCredential{CredentialQueryID: id, Claims: claims}
}

func TestEmail(t *testing.T) {
	mdoc := func(email any) map[string]any {
		return map[string]any{namespaceMdoc: map[string]any{claimMdocEmail: email}}
	}

	testCases := []struct {
		name        string
		result      *verifier.VerifyResponseResult
		expected    string
		expectError bool
	}{
		{"ShouldErrorOnNil", nil, "", true},
		{"ShouldErrorOnNoCredentials", &verifier.VerifyResponseResult{}, "", true},
		{"ShouldReadSDJWT", &verifier.VerifyResponseResult{Credentials: []verifier.VerifiedCredential{credential(querySDJWT, map[string]any{"email": "a@example.com"})}}, "a@example.com", false},
		{"ShouldReadMdoc", &verifier.VerifyResponseResult{Credentials: []verifier.VerifiedCredential{credential(queryMdoc, mdoc("a@example.com"))}}, "a@example.com", false},
		{"ShouldNotReadMdocClaimFromSDJWT", &verifier.VerifyResponseResult{Credentials: []verifier.VerifiedCredential{credential(querySDJWT, mdoc("a@example.com"))}}, "", true},
		{"ShouldNotReadSDJWTClaimFromMdoc", &verifier.VerifyResponseResult{Credentials: []verifier.VerifiedCredential{credential(queryMdoc, map[string]any{"email": "a@example.com"})}}, "", true},
		{"ShouldNotReadNonString", &verifier.VerifyResponseResult{Credentials: []verifier.VerifiedCredential{credential(queryMdoc, mdoc(1))}}, "", true},
		{"ShouldErrorOnUnknownQuery", &verifier.VerifyResponseResult{Credentials: []verifier.VerifiedCredential{credential("other", map[string]any{"email": "a@example.com"})}}, "", true},
		{"ShouldErrorOnDifferentEmails", &verifier.VerifyResponseResult{Credentials: []verifier.VerifiedCredential{
			credential(querySDJWT, map[string]any{"email": "a@example.com"}),
			credential(queryMdoc, mdoc("b@example.com")),
		}}, "", true},
		{"ShouldAcceptSameEmails", &verifier.VerifyResponseResult{Credentials: []verifier.VerifiedCredential{
			credential(querySDJWT, map[string]any{"email": "a@example.com"}),
			credential(queryMdoc, mdoc("a@example.com")),
		}}, "a@example.com", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := Email(tc.result)

			assert.Equal(t, tc.expected, actual)

			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestEmailMatches(t *testing.T) {
	testCases := []struct {
		name      string
		emails    []string
		presented string
		expected  bool
	}{
		{"ShouldMatchExact", []string{"a@example.com"}, "a@example.com", true},
		{"ShouldMatchSecondAddress", []string{"b@example.com", "a@example.com"}, "a@example.com", true},
		{"ShouldMatchASCIICase", []string{"A@Example.com"}, "a@example.com", true},
		{"ShouldNotMatchNothing", nil, "a@example.com", false},
		{"ShouldNotMatchOther", []string{"b@example.com"}, "a@example.com", false},
		{"ShouldNotFoldKelvinSign", []string{"k@example.com"}, "K@example.com", false},
		{"ShouldNotFoldUnicodeCase", []string{"é@example.com"}, "É@example.com", false},
		{"ShouldMatchExactUnicode", []string{"é@example.com"}, "é@example.com", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, EmailMatches(tc.emails, tc.presented))
		})
	}
}
