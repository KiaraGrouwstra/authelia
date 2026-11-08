// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package eudiwallet

import (
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/idfoundry/oid4vcgo/verifier"
)

const (
	querySDJWT = "pid_sd_jwt"
	queryMdoc  = "pid_mdoc"

	claimSDJWTEmail = "email"
	claimMdocEmail  = "email_address"

	namespaceMdoc = "eu.europa.ec.eudi.pid.1"
)

// ErrNoEmail is returned when a presentation holds no usable email address.
var ErrNoEmail = errors.New("the presentation holds no email address")

// Email returns the email address of a verified presentation. It reads each credential in the shape of the query the
// credential answers, and it refuses a presentation with different addresses.
func Email(result *verifier.VerifyResponseResult) (email string, err error) {
	if result == nil {
		return "", ErrNoEmail
	}

	for _, credential := range result.Credentials {
		var value string

		switch credential.CredentialQueryID {
		case querySDJWT:
			value, _ = credential.Claims[claimSDJWTEmail].(string)
		case queryMdoc:
			elements, _ := credential.Claims[namespaceMdoc].(map[string]any)
			value, _ = elements[claimMdocEmail].(string)
		default:
			return "", fmt.Errorf("the presentation answers the unknown query '%s'", credential.CredentialQueryID)
		}

		if value == "" {
			continue
		}

		if email != "" && email != value {
			return "", errors.New("the presentation holds different email addresses")
		}

		email = value
	}

	if email == "" {
		return "", ErrNoEmail
	}

	return email, nil
}

// EmailMatches returns true when the presented email address is one of the account email addresses. The comparison
// ignores case only when both values are ASCII, because Unicode case folding makes different addresses equal: the
// Kelvin sign folds to the letter k.
func EmailMatches(accountEmails []string, presented string) bool {
	for _, email := range accountEmails {
		if email == presented {
			return true
		}

		if isASCII(email) && isASCII(presented) && strings.EqualFold(email, presented) {
			return true
		}
	}

	return false
}

func isASCII(value string) bool {
	for _, r := range value {
		if r > unicode.MaxASCII {
			return false
		}
	}

	return true
}
