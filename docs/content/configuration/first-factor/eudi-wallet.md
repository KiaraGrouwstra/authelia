---
# SPDX-FileCopyrightText: 2026 Authelia
#
# SPDX-License-Identifier: Apache-2.0

title: "EU Digital Identity Wallet"
description: "Configuring log-in with an EU Digital Identity Wallet as a first factor."
summary: ""
date: 2026-11-08T00:00:00+00:00
draft: false
images: []
weight: 102400
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

Authelia can accept a presentation of Person Identification Data (PID) from an EU Digital Identity Wallet as a first
factor. It uses OpenID for Verifiable Presentations 1.0 with the High Assurance Interoperability Profile. It accepts
SD-JWT VC and ISO mdoc credentials.

Authelia reads the email address from the credential. It finds the user in the authentication backend with this email
address. The log-in succeeds only if the user exists and the address is one of the addresses of the user. The
authentication backend must support a search by email address. For LDAP, the users filter must match the email
address.

The log-in counts as one factor of the possession type. A rule with the `two_factor` policy then asks for the password
of the user as the second factor.

## Configuration

{{< config-alert-example >}}

```yaml {title="configuration.yml"}
eudi_wallet:
  enable: true
  authelia_url: 'https://auth.example.com'
  flows:
    - 'same_device'
    - 'cross_device'
    - 'digital_credentials'
  lifetime: '5 minutes'
  certificate_chain: |
    -----BEGIN CERTIFICATE-----
    ...
    -----END CERTIFICATE-----
  private_key: |
    -----BEGIN PRIVATE KEY-----
    ...
    -----END PRIVATE KEY-----
  trusted_issuer_roots:
    - |
      -----BEGIN CERTIFICATE-----
      ...
      -----END CERTIFICATE-----
  crl_urls:
    - 'https://pki.example.com/issuer.crl'
  disable_revocation_check: false
  disable_status_check: false
  vct_values:
    - 'urn:eudi:pid:1'
  mdoc_doc_type: 'eu.europa.ec.eudi.pid.1'
```

## Options

### enable

{{< confkey type="boolean" default="false" required="no" >}}

Enables log-in with an EU Digital Identity Wallet.

### authelia_url

{{< confkey type="string" syntax="uri" required="yes" >}}

The portal URL which offers the wallet log-in. The scheme must be `https`. The value must be equal to the `authelia_url`
of one [session cookie](../session/introduction.md). The wallet log-in does not work on the other portal URLs.

### flows

{{< confkey type="list(string)" default="same_device, cross_device, digital_credentials" required="no" >}}

The log-in flows to offer:

- `same_device`: the browser opens the wallet on the same device. The wallet returns the user to the browser.
- `cross_device`: the browser shows a QR code. The user scans it with a wallet on another device.
- `digital_credentials`: the browser calls the W3C Digital Credentials API. The portal offers this flow only in browsers
  which have the API. In these browsers it replaces `same_device`.

### lifetime

{{< confkey type="string,integer" syntax="duration" default="5 minutes" required="no" >}}

The lifetime of a presentation transaction. The maximum is 1 hour.

### certificate_chain

{{< confkey type="string" syntax="x509_certificate_chain" required="yes" >}}

The Relying Party access certificate chain which signs the presentation requests, with the leaf certificate first. The
leaf certificate must not be self-signed. For use with production wallets, a provider of access certificates in a
Member State must issue the certificate.

### private_key

{{< confkey type="string" syntax="x509_private_key" required="yes" >}}

The P-256 private key of the leaf certificate.

### trusted_issuer_roots

{{< confkey type="list(string)" syntax="x509_certificate_chain" required="yes" >}}

The root certificates of the PID providers to trust.

### crl_issuers

{{< confkey type="list(string)" syntax="x509_certificate_chain" required="no" >}}

The certificates which may sign the certificate revocation lists. The default is the value of `trusted_issuer_roots`.

### crl_urls

{{< confkey type="list(string)" syntax="uri" required="situational" >}}

The certificate revocation lists to check the issuer certificates against. This option is required unless
`disable_revocation_check` is `true`. If Authelia cannot get a valid list, the wallet log-in fails. The other log-in
methods continue to work.

### disable_revocation_check

{{< confkey type="boolean" default="false" required="no" >}}

Disables the certificate revocation check of the issuers. Do not use this option in production.

### disable_status_check

{{< confkey type="boolean" default="false" required="no" >}}

Disables the check of the credential status list. Do not use this option in production.

### vct_values

{{< confkey type="list(string)" default="urn:eudi:pid:1" required="no" >}}

The SD-JWT VC types to accept as PID.

### mdoc_doc_type

{{< confkey type="string" default="eu.europa.ec.eudi.pid.1" required="no" >}}

The ISO mdoc document type to accept as PID.

## Security Considerations

- The account match relies on the email address in the PID. The PID rulebook does not state that providers verify this
  address. Only trust a PID provider if you know that it verifies the address. If a provider lets a person state any
  address, this person can log in to the account which has the address.
- The `cross_device` flow is open to relay attacks: an attacker can show the QR code of a session of the attacker to a
  victim. Do not enable this flow if this risk is not acceptable.
