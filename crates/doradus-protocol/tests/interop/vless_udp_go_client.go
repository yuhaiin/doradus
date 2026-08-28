//go:build ignore

package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/Asutorufa/doradus/pkg/net/netapi"
	"github.com/Asutorufa/doradus/pkg/net/proxy/direct"
	"github.com/Asutorufa/doradus/pkg/net/proxy/fixed"
	"github.com/Asutorufa/doradus/pkg/net/proxy/vless"
)

func main() {
	listen := os.Getenv("VLESS_UDP_LISTEN")
	host, portText, err := net.SplitHostPort(listen)
	if err != nil {
		failf("split listener %q: %v", listen, err)
	}
	var port int
	if _, err := fmt.Sscanf(portText, "%d", &port); err != nil {
		failf("parse listener port %q: %v", portText, err)
	}
	parent, err := fixed.NewClientv2(fixed.ConfigV2{
		Addresses: []fixed.ConfigAddress{{Host: host, Port: int32(port)}},
	}, direct.NewDirect())
	if err != nil {
		failf("fixed parent: %v", err)
	}
	proxy, err := vless.NewClient(vless.Config{
		UUID: "00112233-4455-6677-8899-aabbccddeeff",
	}, parent)
	if err != nil {
		failf("VLESS client: %v", err)
	}
	target, err := netapi.ParseAddress("udp", "example.com:53")
	if err != nil {
		failf("target: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := proxy.PacketConn(ctx, target)
	if err != nil {
		failf("VLESS UDP packet conn: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.WriteTo([]byte("go-vless-udp"), nil); err != nil {
		failf("VLESS UDP write: %v", err)
	}
	response := make([]byte, 64)
	n, _, err := conn.ReadFrom(response)
	if err != nil {
		failf("VLESS UDP read: %v", err)
	}
	if string(response[:n]) != "go-vless-udp" {
		failf("VLESS UDP response = %q", response[:n])
	}
}

func failf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
