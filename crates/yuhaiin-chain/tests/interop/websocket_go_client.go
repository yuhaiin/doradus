//go:build ignore

// This probe uses the real Go fixed -> websocket -> http2 -> yuubinsya
// client chain against the Rust WebSocket+HTTP/2 server fixture.
package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/fixed"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/http2/v2"
	tlsproxy "github.com/Asutorufa/yuhaiin/pkg/net/proxy/tls"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/websocket"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/yuubinsya"
)

const password = "rust-go-websocket-interop"

func main() {
	if len(os.Args) != 3 {
		failf("usage: websocket_go_client <server-addr> <target-addr>")
	}
	host, port := splitAddr(os.Args[1])
	target := parseAddr(os.Args[2])
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	fixedClient, err := fixed.NewClient(fixed.Config{Host: host, Port: int32(port)}, nil)
	if err != nil {
		failf("Go fixed client: %v", err)
	}
	if os.Getenv("WEBSOCKET_TLS") == "1" {
		fixedClient, err = tlsproxy.NewClient(tlsproxy.TLSConfig{
			Enable:             true,
			ServerNames:        []string{"localhost"},
			InsecureSkipVerify: true,
		}, fixedClient)
		if err != nil {
			failf("Go TLS client: %v", err)
		}
	}
	websocketClient, err := websocket.NewClient(websocket.Config{
		Host: "localhost",
		Path: "/proxy/ws",
	}, fixedClient)
	if err != nil {
		failf("Go WebSocket client: %v", err)
	}
	h2Client, err := http2.NewClient(http2.Config{Concurrency: 10}, websocketClient)
	if err != nil {
		failf("Go HTTP/2 client: %v", err)
	}
	client, err := yuubinsya.NewClient(yuubinsya.Config{Password: password}, h2Client)
	if err != nil {
		failf("Go Yuubinsya client: %v", err)
	}
	defer client.Close()

	conn, err := client.Conn(ctx, target)
	if err != nil {
		failf("Go WebSocket chain connect: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	payload := []byte("go-websocket-echo")
	if _, err := conn.Write(payload); err != nil {
		failf("Go WebSocket chain write: %v", err)
	}
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, response); err != nil {
		failf("Go WebSocket chain read: %v", err)
	}
	if string(response) != string(payload) {
		failf("Go WebSocket chain response = %q, want %q", response, payload)
	}
}

func parseAddr(value string) netapi.Address {
	addr, err := netapi.ParseAddress("tcp", value)
	if err != nil {
		failf("parse target %q: %v", value, err)
	}
	return addr
}

func splitAddr(value string) (string, int) {
	host, portText, err := net.SplitHostPort(value)
	if err != nil {
		failf("split server address %q: %v", value, err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		failf("parse server port %q: %v", portText, err)
	}
	return host, port
}

func failf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
