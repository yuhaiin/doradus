package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/Asutorufa/doradus/pkg/net/netapi"
	"github.com/Asutorufa/doradus/pkg/net/proxy/direct"
	"github.com/Asutorufa/doradus/pkg/net/proxy/fixed"
	tlsproxy "github.com/Asutorufa/doradus/pkg/net/proxy/tls"
	"github.com/Asutorufa/doradus/pkg/net/proxy/vmess"
	websocketproxy "github.com/Asutorufa/doradus/pkg/net/proxy/websocket"
)

func main() {
	listen := os.Getenv("VMESS_LISTEN")
	host, portText, err := net.SplitHostPort(listen)
	if err != nil {
		panic(err)
	}
	var port int
	if _, err := fmt.Sscanf(portText, "%d", &port); err != nil {
		panic(err)
	}
	parent, err := fixed.NewClientv2(fixed.ConfigV2{
		Addresses: []fixed.ConfigAddress{{Host: host, Port: int32(port)}},
	}, direct.NewDirect())
	if err != nil {
		panic(err)
	}
	var dialer netapi.Proxy = parent
	if os.Getenv("VMESS_TRANSPORT") == "tls-websocket" {
		dialer, err = tlsproxy.NewClient(tlsproxy.TLSConfig{
			Enable:             true,
			ServerNames:        []string{"localhost"},
			InsecureSkipVerify: true,
		}, dialer)
		if err != nil {
			panic(err)
		}
		dialer, err = websocketproxy.NewClient(websocketproxy.Config{
			Host: "localhost",
			Path: "/vmess",
		}, dialer)
		if err != nil {
			panic(err)
		}
	}
	proxy, err := vmess.NewClient(vmess.Config{
		UUID:     "00112233-4455-6677-8899-aabbccddeeff",
		AlterID:  "0",
		Security: "aes-128-gcm",
	}, dialer)
	if err != nil {
		panic(err)
	}
	target, err := netapi.ParseAddressPort("tcp", "example.com", 443)
	if err != nil {
		panic(err)
	}
	conn, err := proxy.Conn(context.Background(), target)
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		panic(err)
	}
	response := make([]byte, 4)
	if _, err := io.ReadFull(conn, response); err != nil {
		panic(err)
	}
	if string(response) != "pong" {
		panic("unexpected response")
	}
}
