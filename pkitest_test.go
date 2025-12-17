// SPDX-License-Identifier: GPL-3.0-or-later

package pkitest

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/bassosimone/runtimex"
	"github.com/stretchr/testify/assert"
)

// This test ensures that the PKI type works as intended with HTTP code.
func TestPKIWorksWithHTTPCode(t *testing.T) {
	// create the testing PKI and the certificate
	tempdir := runtimex.PanicOnError1(os.MkdirTemp("", ""))
	defer os.RemoveAll(tempdir)
	pki := MustNewPKI(tempdir)
	config := &SelfSignedCertConfig{
		CommonName:   "www.example.com",
		DNSNames:     []string{"www.example.com"},
		IPAddrs:      []net.IP{net.IPv4(127, 0, 0, 1)},
		Organization: []string{"Example"},
	}
	cert := pki.MustNewCert(config)

	// create and start a testing server using the certificate
	expected := []byte("Hello, world!\n")
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Write(expected)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()

	// obtain the server address and port
	baseURL := runtimex.PanicOnError1(url.Parse(server.URL))
	t.Log(baseURL)
	_, sport := runtimex.PanicOnError2(net.SplitHostPort(baseURL.Host))

	// create a client using the corresponding cert pool
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, baseURL.Host)
			},
			TLSClientConfig: &tls.Config{
				NextProtos: []string{"h2", "http/1.1"},
				RootCAs:    pki.CertPool(),
			},
			ForceAttemptHTTP2: true,
		},
	}

	// test the common name and the SANs cases
	hosts := []string{"www.example.com", "127.0.0.1"}
	for _, host := range hosts {
		t.Run(host, func(t *testing.T) {
			// reconstruct the correct URL
			URL := &url.URL{
				Scheme: "https",
				Host:   net.JoinHostPort(host, sport),
				Path:   "/",
			}

			// perform the round trip
			resp, err := client.Get(URL.String())
			assert.NoError(t, err)
			assert.True(t, resp.StatusCode == http.StatusOK)
			defer resp.Body.Close()

			// ensure the body is as expected
			respBody, err := io.ReadAll(resp.Body)
			assert.Equal(t, expected, respBody)
		})
	}
}

// This test ensures we regenerate expired certificates
func TestRegenerateCertificate(t *testing.T) {
	// create the testing PKI and the certificate
	tempdir := runtimex.PanicOnError1(os.MkdirTemp("", ""))
	pki := MustNewPKI(tempdir)
	config := &SelfSignedCertConfig{
		CommonName:   "www.example.com",
		DNSNames:     []string{"www.example.com"},
		ExpireAfter:  time.Hour, // small expiry forces regeneration
		IPAddrs:      []net.IP{net.IPv4(127, 0, 0, 1)},
		Organization: []string{"Example"},
	}

	// create a first certificate
	cert1 := pki.MustNewCert(config)

	// create a second certificate
	cert2 := pki.MustNewCert(config)

	// the underlying raw certs must differ
	assert.NotEqual(t, cert1.Certificate, cert2.Certificate)
}

// This test ensures we use the cached certificate.
func TestUsesCache(t *testing.T) {
	// create the testing PKI and the certificate
	tempdir := runtimex.PanicOnError1(os.MkdirTemp("", ""))
	pki := MustNewPKI(tempdir)
	config := &SelfSignedCertConfig{
		CommonName:   "www.example.com",
		DNSNames:     []string{"www.example.com"},
		ExpireAfter:  0, // default is one year
		IPAddrs:      []net.IP{net.IPv4(127, 0, 0, 1)},
		Organization: []string{"Example"},
	}

	// create a first certificate
	cert1 := pki.MustNewCert(config)

	// create a second certificate
	cert2 := pki.MustNewCert(config)

	// the underlying raw certs must be equal
	assert.Equal(t, cert1.Certificate, cert2.Certificate)
}
