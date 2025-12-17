# Golang PKI Simulator for testing

[![GoDoc](https://pkg.go.dev/badge/github.com/bassosimone/pkitest)](https://pkg.go.dev/github.com/bassosimone/pkitest) [![Build Status](https://github.com/bassosimone/pkitest/actions/workflows/go.yml/badge.svg)](https://github.com/bassosimone/pkitest/actions) [![codecov](https://codecov.io/gh/bassosimone/pkitest/branch/main/graph/badge.svg)](https://codecov.io/gh/bassosimone/pkitest)

The `pkitest` Go package allows simulating a Public Key Infrastructure (PKI) to
write more realistic integration tests.

Basic usage is like:

```Go
import "github.com/bassosimone/pkitest"

// 1. Create the PKI inside the given cache directory.
pki := pkitest.MustNewPKI("testdata")

// 2. Create a configuration for your server's certificate.
config := &SelfSignedCertConfig{
	CommonName:   "www.example.com",
	DNSNames:     []string{"www.example.com"},
	IPAddrs:      []net.IP{net.IPv4(127, 0, 0, 1)},
	Organization: []string{"Example"},
}

// 3. Generate the certificate for the server. This is cached on disk.
cert := pki.MustNewCert(config)

// 4. Use the certificate in the TLS server config.
serverConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

// 5. Use the certificate in the TLS client config.
clientConfig := &tls.Config{RootCAs: pki.CertPool()}
```

## Features

- **Easy PKI simulation:** Create a PKI with a single line of code.

- **Self-signed certificates:** Generate self-signed certificates for your tests.

- **Caching:** Certificates are cached on disk to speed up tests.

- **Automatic renewal:** Certificates are automatically renewed if expired or about to expire.

- **Concurrency safe:** The PKI is safe for concurrent use in parallel tests.

- **Test friendly:** Panic on failure to avoid unnecessary `if err != nil` checks.

## Caching and Renewal

Certificates are cached in the directory provided to `MustNewPKI`. By default,
they expire after one year. When a certificate is expired or expiring within 30
days, `MustNewCert` automatically renews it. This ensures that tests run fast,
except when certificates need to be regenerated.

The cache key is a SHA256 hash of the certificate's configuration, so any
difference in the common name, DNS names, or IP addresses will result in
a difference cache entry and certificate.

## Installation

To add this package as a dependency to your module:

```sh
go get github.com/bassosimone/pkitest
```

## Development

To run the tests:
```sh
go test -v .
```

To measure test coverage:
```sh
go test -v -cover .
```

## License

```
SPDX-License-Identifier: GPL-3.0-or-later
```
