//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Adapted from: https://github.com/rbmk-project/rbmk/blob/v0.17.0/pkg/common/selfsignedcert/selfsignedcert.go
// Adapted from: https://github.com/rbmk-project/rbmk/blob/v0.17.0/pkg/x/netsim/simpki/simpki.go
//

// Package pkitest allows to simulate a PKI for testing purposes.
//
// It allows to generate self-signed certificates and to cache them in
// a directory to avoid regenerating them at every run. This package uses
// a "web of trust" model, where each generated certificate is self-signed
// and the client gets all such certificates into a cert pool.
//
// Because this package is only meant to run as part of integration
// tests, all the functions panic on failure.
package pkitest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/bassosimone/runtimex"
	"github.com/rogpeppe/go-internal/lockedfile"
)

// SelfSignedCertConfig contains configuration for [MustNewSelfSignedCert].
type SelfSignedCertConfig struct {
	// CommonName is the MANDATORY certificate common name.
	CommonName string

	// DNSNames contains the MANDATORY alternative DNS names to include in the certificate.
	DNSNames []string

	// ExpireAfter contains the OPTIONAL maximum certificate duration.
	//
	// If not set, we use one year.
	ExpireAfter time.Duration

	// IPAddrs contains the OPTIONAL IP addrs for which the certificate is valid.
	//
	// If not set, the certificate won't have any SANs.
	IPAddrs []net.IP

	// Organization contains MANDATORY the organization to use.
	Organization []string
}

// SelfSignedCert is the self-signed certificate.
type SelfSignedCert struct {
	// CertPEM is the certificate encoded using PEM.
	CertPEM []byte

	// KeyPEM is the secret key encoded using PEM.
	KeyPEM []byte
}

// MustWriteFiles writes CertPEM to `cert.pem` and KeyPEM to `key.pem`.
//
// This method panics on failure.
func (c *SelfSignedCert) MustWriteFiles(baseDir string) {
	runtimex.PanicOnError0(os.WriteFile(filepath.Join(baseDir, "cert.pem"), c.CertPEM, 0600))
	runtimex.PanicOnError0(os.WriteFile(filepath.Join(baseDir, "key.pem"), c.KeyPEM, 0600))
}

// MustNewSelfSignedCert generates a self-signed certificate and key with SANs.
//
// This function panics on failure.
func MustNewSelfSignedCert(config *SelfSignedCertConfig) *SelfSignedCert {
	// Generate the private key
	priv := runtimex.PanicOnError1(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))

	// Build the certificate template
	notBefore := time.Now()
	expireAfter := 365 * 24 * time.Hour
	if config.ExpireAfter > 0 {
		expireAfter = config.ExpireAfter
	}
	notAfter := notBefore.Add(expireAfter)
	serialNumber := runtimex.PanicOnError1(rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128)))
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: config.Organization,
			CommonName:   config.CommonName,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Add SANs to the certificate
	template.DNSNames = config.DNSNames
	template.IPAddresses = config.IPAddrs

	// Generate the certificate proper and encoded to PEM
	certDER := runtimex.PanicOnError1(x509.CreateCertificate(
		rand.Reader, &template, &template, &priv.PublicKey, priv))
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// Generate the private key in PEM format
	keyPEM := runtimex.PanicOnError1(x509.MarshalECPrivateKey(priv))
	keyPEMBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyPEM})

	// Return the results
	return &SelfSignedCert{CertPEM: certPEM, KeyPEM: keyPEMBytes}
}

// PKI models the public key infrastructure.
//
// The PKI struct is safe for concurrent use from multiple goroutines,
// making it suitable for parallel tests.
//
// Construct using [MustNewPKI].
type PKI struct {
	cacheDir string
	pool     *x509.CertPool
}

// MustNewPKI constructs a new [*PKI] instance using
// the given filesystem directory to store the
// certificates, to avoid regenerating them every
// time we run integration tests.
//
// This function panics on failure.
func MustNewPKI(cacheDir string) *PKI {
	return &PKI{
		cacheDir: cacheDir,
		pool:     x509.NewCertPool(),
	}
}

// pkiConfigCacheKey computes a deterministic SHA256 hash of the entire config.
// This ensures that certificates are cached based on all their properties
// (CommonName, DNSNames, and IPAddrs), not just the CommonName alone.
//
// The hash is computed by concatenating the CommonName with sorted DNSNames
// and sorted IPAddrs to ensure deterministic ordering.
func pkiConfigCacheKey(config *SelfSignedCertConfig) string {
	h := sha256.New()

	// Hash CommonName
	h.Write([]byte(config.CommonName))
	h.Write([]byte{0}) // separator

	// Hash sorted DNSNames
	dnsNames := make([]string, len(config.DNSNames))
	copy(dnsNames, config.DNSNames)
	sort.Strings(dnsNames)
	for _, name := range dnsNames {
		h.Write([]byte(name))
		h.Write([]byte{0}) // separator
	}

	// Hash sorted IPAddrs
	ipAddrs := make([]string, len(config.IPAddrs))
	for i, ip := range config.IPAddrs {
		ipAddrs[i] = ip.String()
	}
	sort.Strings(ipAddrs)
	for _, ip := range ipAddrs {
		h.Write([]byte(ip))
		h.Write([]byte{0}) // separator
	}

	return hex.EncodeToString(h.Sum(nil))
}

// MustNewCert creates the certificate using the given
// [*SelfSignedCertConfig] and using the cache directory
// to avoid regenerating the certificate every time.
//
// Certificates are cached using a SHA256 hash of the entire config
// (CommonName, DNSNames, and IPAddrs). This means that:
//
//   - Same config = same cached certificate (deterministic)
//
//   - Different SANs or IPs = different certificate
//
//   - Cache uses git-style directory structure (e.g., pkistore/ab/cd/abcdef.../)
//     for better filesystem performance with many certificates
//
// Certificates are automatically regenerated if they are expired or
// expiring within 30 days.
//
// It returns the [tls.Certificate] to use in server code.
//
// As a side effect, this method also updates the
// certificate pool you can get with [*PKI.CertPool].
//
// This function panics on failure.
func (pki *PKI) MustNewCert(config *SelfSignedCertConfig) tls.Certificate {
	// ensure there are no race conditions with concurrent invocations
	baseDir := filepath.Join(pki.cacheDir, "certs")
	runtimex.PanicOnError0(os.MkdirAll(baseDir, 0700))
	mu := lockedfile.MutexAt(filepath.Join(baseDir, ".lock"))
	unlock := runtimex.PanicOnError1(mu.Lock())
	defer unlock()

	// compute cache key from entire config (CommonName + DNSNames + IPAddrs)
	cacheKey := pkiConfigCacheKey(config)

	// use git-style three-level directory structure: ab/cd/abcdef...
	// this improves filesystem performance when storing many certificates
	runtimex.Assert(len(cacheKey) >= 4)
	dirpath := filepath.Join(baseDir, cacheKey[0:2], cacheKey[2:4], cacheKey[4:])
	runtimex.PanicOnError0(os.MkdirAll(dirpath, 0700))

	// check whether cert.pem already exists
	certPEM := filepath.Join(dirpath, "cert.pem")
	hasCertPEM := false
	if sbuf, err := os.Stat(certPEM); err == nil && sbuf.Mode().IsRegular() {
		hasCertPEM = true
	}

	// check whether key.pem already exists
	keyPEM := filepath.Join(dirpath, "key.pem")
	hasKeyPEM := false
	if sbuf, err := os.Stat(keyPEM); err == nil && sbuf.Mode().IsRegular() {
		hasKeyPEM = true
	}

	// check if cached certificate is expired or expiring soon (within 30 days)
	// if so, mark for regeneration
	if hasCertPEM && hasKeyPEM {
		certPEMData := runtimex.PanicOnError1(os.ReadFile(certPEM))
		block, unused := pem.Decode(certPEMData)
		_ = unused
		if block != nil && block.Type == "CERTIFICATE" {
			cert := runtimex.PanicOnError1(x509.ParseCertificate(block.Bytes))
			expiryThreshold := time.Now().Add(30 * 24 * time.Hour)
			if cert.NotAfter.Before(expiryThreshold) {
				// certificate is expired or expiring soon, regenerate
				hasCertPEM, hasKeyPEM = false, false
			}
		}
	}

	// regenerate the certificate if we miss either cert.pem or key.pem,
	// or if the certificate is expired/expiring soon
	if !hasCertPEM || !hasKeyPEM {
		MustNewSelfSignedCert(config).MustWriteFiles(dirpath)
	}

	// load the certificate and ensure we update the cert pool
	certPEMData := runtimex.PanicOnError1(os.ReadFile(certPEM))
	keyPEMData := runtimex.PanicOnError1(os.ReadFile(keyPEM))
	runtimex.Assert(pki.pool.AppendCertsFromPEM(certPEMData))
	return runtimex.PanicOnError1(tls.X509KeyPair(certPEMData, keyPEMData))
}

// CertPool returns the certificate pool that contains
// all the certificates generated by this PKI.
func (pki *PKI) CertPool() *x509.CertPool {
	return pki.pool
}
