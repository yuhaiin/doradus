//go:build ignore

// This probe uses the legacy Go x/net/http2 transport.  It intentionally
// leaves the underlying TCP dial in the callback so the Rust test can provide
// a prior-knowledge HTTP/2 endpoint without requiring a TLS certificate.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"golang.org/x/net/http2"
)

func main() {
	if len(os.Args) != 2 {
		failf("usage: http2_v1_go_client <server-address>")
	}

	transport := &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, _ string, _ *tls.Config) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, network, os.Args[1])
		},
	}
	defer transport.CloseIdleConnections()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	payload := []byte("go-http2-v1-to-rust")
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodConnect,
		"https://localhost",
		bytes.NewReader(payload),
	)
	if err != nil {
		failf("build CONNECT request: %v", err)
	}
	response, err := transport.RoundTrip(request)
	if err != nil {
		failf("HTTP/2 v1 round trip: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		failf("HTTP/2 v1 response status = %s", response.Status)
	}
	echo, err := io.ReadAll(response.Body)
	if err != nil {
		failf("HTTP/2 v1 response body: %v", err)
	}
	if string(echo) != string(payload) {
		failf("HTTP/2 v1 response = %q, want %q", echo, payload)
	}
}

func failf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
