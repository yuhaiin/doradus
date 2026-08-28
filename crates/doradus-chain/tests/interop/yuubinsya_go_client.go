//go:build ignore

// This probe is executed by the ignored Rust/Go interoperability test with
// `go run` from the Go checkout.  It deliberately uses the real Go
// fixed+yuubinsya client instead of duplicating the wire format here.
package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/Asutorufa/doradus/pkg/net/netapi"
	"github.com/Asutorufa/doradus/pkg/net/proxy/fixed"
	"github.com/Asutorufa/doradus/pkg/net/proxy/yuubinsya"
)

const password = "rust-go-interop"

func main() {
	if len(os.Args) != 4 {
		failf("usage: yuubinsya_go_client <server-tcp-udp-addr> <tcp-target> <udp-target>")
	}

	serverHost, serverPort := splitAddr(os.Args[1])
	tcpTarget := parseAddr("tcp", os.Args[2])
	udpTarget := parseAddr("udp", os.Args[3])
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	runTCP(ctx, serverHost, serverPort, tcpTarget)
	runUOT(ctx, serverHost, serverPort, udpTarget)
	runNativeUDP(ctx, serverHost, serverPort, udpTarget)
	runPing(ctx, serverHost, serverPort, tcpTarget)
}

func runTCP(ctx context.Context, host string, port int, target netapi.Address) {
	client := newClient(host, port, false)
	defer client.Close()
	conn, err := client.Conn(ctx, target)
	if err != nil {
		failf("Go Yuubinsya TCP connect: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	payload := []byte("go-to-rust-tcp")
	if _, err := conn.Write(payload); err != nil {
		failf("Go Yuubinsya TCP write: %v", err)
	}
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, response); err != nil {
		failf("Go Yuubinsya TCP read: %v", err)
	}
	if string(response) != string(payload) {
		failf("Go Yuubinsya TCP response = %q, want %q", response, payload)
	}
}

func runUOT(ctx context.Context, host string, port int, target netapi.Address) {
	client := newClient(host, port, true)
	defer client.Close()
	packet, err := client.PacketConn(ctx, target)
	if err != nil {
		failf("Go Yuubinsya UOT connect: %v", err)
	}
	defer packet.Close()
	payload := []byte("go-to-rust-uot")
	if _, err := packet.WriteTo(payload, target); err != nil {
		failf("Go Yuubinsya UOT write: %v", err)
	}
	_ = packet.SetReadDeadline(time.Now().Add(5 * time.Second))
	response := make([]byte, 1024)
	length, _, err := packet.ReadFrom(response)
	if err != nil {
		failf("Go Yuubinsya UOT read: %v", err)
	}
	if string(response[:length]) != string(payload) {
		failf("Go Yuubinsya UOT response = %q, want %q", response[:length], payload)
	}
}

func runNativeUDP(ctx context.Context, host string, port int, target netapi.Address) {
	client := newClient(host, port, false)
	defer client.Close()
	packet, err := client.PacketConn(ctx, target)
	if err != nil {
		failf("Go Yuubinsya native UDP connect: %v", err)
	}
	defer packet.Close()
	payload := []byte("go-to-rust-udp")
	if _, err := packet.WriteTo(payload, target); err != nil {
		failf("Go Yuubinsya native UDP write: %v", err)
	}
	_ = packet.SetReadDeadline(time.Now().Add(5 * time.Second))
	response := make([]byte, 1024)
	length, _, err := packet.ReadFrom(response)
	if err != nil {
		failf("Go Yuubinsya native UDP read: %v", err)
	}
	if string(response[:length]) != string(payload) {
		failf("Go Yuubinsya native UDP response = %q, want %q", response[:length], payload)
	}
}

func runPing(ctx context.Context, host string, port int, target netapi.Address) {
	client := newClient(host, port, false)
	defer client.Close()
	if _, err := client.Ping(ctx, target); err != nil {
		failf("Go Yuubinsya ping: %v", err)
	}
}

func newClient(host string, port int, overTCP bool) netapi.Proxy {
	fixedClient, err := fixed.NewClient(fixed.Config{Host: host, Port: int32(port)}, nil)
	if err != nil {
		failf("Go fixed client: %v", err)
	}
	client, err := yuubinsya.NewClient(yuubinsya.Config{
		Password:      password,
		UDPOverStream: overTCP,
	}, fixedClient)
	if err != nil {
		failf("Go Yuubinsya client: %v", err)
	}
	return client
}

func parseAddr(network, value string) netapi.Address {
	addr, err := netapi.ParseAddress(network, value)
	if err != nil {
		failf("parse %s target %q: %v", network, value, err)
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
