// SPDX-License-Identifier: GPL-3.0-or-later

package pkitest

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
)

// Example_package demonstrates how to use pkitest to set up a TLS server
// and a corresponding client that trusts it.
func Example_package() {
	// 1. Create a PKI instance backed by a temporary cache directory. In a real test
	// suite, you might create this once in your TestMain.
	tempdir, err := os.MkdirTemp("", "")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(tempdir)
	pki := MustNewPKI(tempdir)

	// 2. Create a configuration for your server's certificate.
	config := &SelfSignedCertConfig{
		CommonName:   "www.example.com",
		DNSNames:     []string{"www.example.com"},
		IPAddrs:      []net.IP{net.IPv4(127, 0, 0, 1)},
		Organization: []string{"Example"},
	}

	// 3. Generate the certificate for the server. This is cached on disk.
	cert := pki.MustNewCert(config)

	// 4. Start a TLS server using the generated certificate.
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello, world!"))
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()

	// 5. Create an HTTP client configured to trust the PKI's certificates.
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				NextProtos: []string{"h2", "http/1.1"},
				RootCAs:    pki.CertPool(),
			},
			ForceAttemptHTTP2: true,
		},
	}

	// 6. Make a successful request to the server.
	resp, err := client.Get(server.URL)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(body))

	// Output:
	// Hello, world!
}
