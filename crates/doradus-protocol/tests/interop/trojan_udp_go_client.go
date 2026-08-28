//go:build ignore

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/Asutorufa/doradus/pkg/net/netapi"
	"github.com/Asutorufa/doradus/pkg/net/proxy/direct"
	"github.com/Asutorufa/doradus/pkg/net/proxy/fixed"
	"github.com/Asutorufa/doradus/pkg/net/proxy/socks5/tools"
	"github.com/Asutorufa/doradus/pkg/net/proxy/trojan"
)

func main() {
	listen := os.Getenv("TROJAN_UDP_LISTEN")
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
	proxy, err := trojan.NewClient(trojan.Config{Password: "secret"}, parent)
	if err != nil {
		failf("Trojan client: %v", err)
	}
	target, err := netapi.ParseAddress("udp", "example.com:53")
	if err != nil {
		failf("target: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := proxy.PacketConn(ctx, target)
	if err != nil {
		failf("Trojan UDP packet conn: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.WriteTo([]byte("go-trojan-udp"), target); err != nil {
		failf("Trojan UDP write: %v", err)
	}
	// The Go reference PacketConn.ReadFrom currently peeks at the four-byte
	// length+CRLF prefix without consuming it. Read the real stream frame here
	// so this interop check validates the standard Trojan UDP wire format.
	stream, ok := conn.(net.Conn)
	if !ok {
		failf("Trojan packet connection is not a stream connection")
	}
	reader := bufio.NewReader(stream)
	_, responseTarget, err := tools.ReadAddr("udp", reader)
	if err != nil {
		failf("Trojan UDP response target: %v", err)
	}
	if responseTarget.String() != target.String() {
		failf("unexpected Trojan UDP target: %s", responseTarget)
	}
	var length uint16
	if err := binary.Read(reader, binary.BigEndian, &length); err != nil {
		failf("Trojan UDP response length: %v", err)
	}
	var crlf [2]byte
	if _, err := io.ReadFull(reader, crlf[:]); err != nil {
		failf("Trojan UDP response delimiter: %v", err)
	}
	if !bytes.Equal(crlf[:], []byte("\r\n")) {
		failf("unexpected Trojan UDP delimiter: %q", crlf)
	}
	response := make([]byte, 64)
	if int(length) > len(response) {
		failf("Trojan UDP response too large: %d", length)
	}
	if _, err := io.ReadFull(reader, response[:length]); err != nil {
		failf("Trojan UDP response: %v", err)
	}
	if string(response[:length]) != "go-trojan-udp" {
		failf("Trojan UDP response = %q", response[:length])
	}
}

func failf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
