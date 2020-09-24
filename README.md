![OAuth2 Proxy](/docs/logos/OAuth2_Proxy_horizontal.svg)

[![Build Status](https://secure.travis-ci.org/oauth2-proxy/oauth2-proxy.svg?branch=master)](http://travis-ci.org/oauth2-proxy/oauth2-proxy)
[![Go Report Card](https://goreportcard.com/badge/github.com/oauth2-proxy/oauth2-proxy)](https://goreportcard.com/report/github.com/oauth2-proxy/oauth2-proxy)
[![GoDoc](https://godoc.org/github.com/oauth2-proxy/oauth2-proxy?status.svg)](https://godoc.org/github.com/oauth2-proxy/oauth2-proxy)
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![Maintainability](https://api.codeclimate.com/v1/badges/a58ff79407212e2beacb/maintainability)](https://codeclimate.com/github/oauth2-proxy/oauth2-proxy/maintainability)
[![Test Coverage](https://api.codeclimate.com/v1/badges/a58ff79407212e2beacb/test_coverage)](https://codeclimate.com/github/oauth2-proxy/oauth2-proxy/test_coverage)

# Oauth2-proxy forked for Liquid Investigations

This fork adds a `liquid` provider to replace <authproxy url>, you can find it under `providers/liquid.go`. All other providers have been disabled.

Environment variables specific for the liquid provider:

- `LIQUID_HTTP_PROTOCOL` - must be set to `http` or `https`
- `LIQUID_DOMAIN` - domain name of the auth provider service, e.g. liquid.example.org 
- `LIQUID_ENABLE_HYPOTHESIS_HEADERS` - if set, sets the X-Forwarded-User header to `acct:USERNAME@LIQUID_DOMAIN` instead of just the username. This is required by Hypothesis only.

Example usage, with other relevant configs set:


- `OAUTH2_PROXY_CLIENT_ID` = CLIENT_ID
- `OAUTH2_PROXY_CLIENT_SECRET` = CLIENT_SECRET
- `OAUTH2_PROXY_COOKIE_SECRET` = "28654d2ed1e9fe3e"
- `OAUTH2_PROXY_EMAIL_DOMAIN` = *
- `OAUTH2_PROXY_HTTP_ADDRESS` = "0.0.0.0:5000"
- `OAUTH2_PROXY_PROVIDER` = "liquid"
- `OAUTH2_PROXY_REDEEM_URL` = "http://10.66.60.1:8768/o/token/"
- `OAUTH2_PROXY_PROFILE_URL` = "http://10.66.60.1:8768/accounts/profile"
- `OAUTH2_PROXY_REDIRECT_URL` = "http://hoover.liquid.example.org/oauth2/callback"
- `OAUTH2_PROXY_COOKIE_HTTPONLY` = false
- `OAUTH2_PROXY_COOKIE_SECURE` = false
- `OAUTH2_PROXY_SKIP_PROVIDER_BUTTON` = true
- `OAUTH2_PROXY_SET_XAUTHREQUEST` = true
- `OAUTH2_PROXY_SSL_INSECURE_SKIP_VERIFY` = true
- `OAUTH2_PROXY_SSL_UPSTREAM_INSECURE_SKIP_VERIFY` = true
- `OAUTH2_PROXY_WHITELIST_DOMAINS` = ".liquid.example.org"
- `OAUTH2_PROXY_REVERSE_PROXY` = true
- `LIQUID_DOMAIN` = liquid.example.org
- `LIQUID_HTTP_PROTOCOL` = http
- `OAUTH2_PROXY_UPSTREAMS` = "http://10.66.60.1:20341"

---


A reverse proxy and static file server that provides authentication using Providers (Google, GitHub, and others)
to validate accounts by email, domain or group.

**Note:** This repository was forked from [bitly/OAuth2_Proxy](https://github.com/bitly/oauth2_proxy) on 27/11/2018.
Versions v3.0.0 and up are from this fork and will have diverged from any changes in the original fork.
A list of changes can be seen in the [CHANGELOG](CHANGELOG.md).

**Note:** This project was formerly hosted as `pusher/oauth2_proxy` but has been renamed as of 29/03/2020 to `oauth2-proxy/oauth2-proxy`.
Going forward, all images shall be available at `quay.io/oauth2-proxy/oauth2-proxy` and binaries wiil been named `oauth2-proxy`.

![Sign In Page](https://cloud.githubusercontent.com/assets/45028/4970624/7feb7dd8-6886-11e4-93e0-c9904af44ea8.png)

## Installation

1.  Choose how to deploy:

    a. Download [Prebuilt Binary](https://github.com/oauth2-proxy/oauth2-proxy/releases) (current release is `v6.1.1`)

    b. Build with `$ go get github.com/oauth2-proxy/oauth2-proxy` which will put the binary in `$GOROOT/bin`

    c. Using the prebuilt docker image [quay.io/oauth2-proxy/oauth2-proxy](https://quay.io/oauth2-proxy/oauth2-proxy) (AMD64, ARMv6 and ARM64 tags available)

Prebuilt binaries can be validated by extracting the file and verifying it against the `sha256sum.txt` checksum file provided for each release starting with version `v3.0.0`.

```
sha256sum -c sha256sum.txt 2>&1 | grep OK
oauth2-proxy-x.y.z.linux-amd64: OK
```

2.  [Select a Provider and Register an OAuth Application with a Provider](https://oauth2-proxy.github.io/oauth2-proxy/auth-configuration)
3.  [Configure OAuth2 Proxy using config file, command line options, or environment variables](https://oauth2-proxy.github.io/oauth2-proxy/configuration)
4.  [Configure SSL or Deploy behind a SSL endpoint](https://oauth2-proxy.github.io/oauth2-proxy/tls-configuration) (example provided for Nginx)


## Security

If you are running a version older than v6.0.0 we **strongly recommend you please update** to a current version.
See [open redirect vulnverability](https://github.com/oauth2-proxy/oauth2-proxy/security/advisories/GHSA-5m6c-jp6f-2vcv) for details.

## Docs

Read the docs on our [Docs site](https://oauth2-proxy.github.io/oauth2-proxy).

![OAuth2 Proxy Architecture](https://cloud.githubusercontent.com/assets/45028/8027702/bd040b7a-0d6a-11e5-85b9-f8d953d04f39.png)

## Getting Involved

If you would like to reach out to the maintainers, come talk to us in the `#oauth2_proxy` channel in the [Gophers slack](http://gophers.slack.com/).

## Contributing

Please see our [Contributing](CONTRIBUTING.md) guidelines. For releasing see our [release creation guide](RELEASE.md).
