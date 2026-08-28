package main

import (
	"context"
	"errors"
	"io"
	"net"
	"os"

	"github.com/Asutorufa/doradus/pkg/net/netapi"
	"github.com/Asutorufa/doradus/pkg/net/proxy/shadowsocks"
)

type fixedProxy struct {
	address string
}

func (p fixedProxy) Conn(ctx context.Context, _ netapi.Address) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "tcp", p.address)
}

func (fixedProxy) PacketConn(context.Context, netapi.Address) (net.PacketConn, error) {
	return nil, errors.New("packet mode is not used by obfs_http")
}

func (fixedProxy) Ping(context.Context, netapi.Address) (uint64, error) {
	return 0, errors.New("ping is not used by obfs_http")
}

func (fixedProxy) Dispatch(_ context.Context, address netapi.Address) (netapi.Address, error) {
	return address, nil
}

func (fixedProxy) Close() error { return nil }

func main() {
	address := os.Getenv("OBFS_LISTEN")
	if address == "" {
		panic("OBFS_LISTEN is empty")
	}
	proxy, err := shadowsocks.NewHTTPOBFS(shadowsocks.HTTPObfsConfig{
		Host: "obfs.example",
		Port: "80",
	}, fixedProxy{address: address})
	if err != nil {
		panic(err)
	}
	destination, err := netapi.ParseAddress("tcp", "example.com:443")
	if err != nil {
		panic(err)
	}
	conn, err := proxy.Conn(context.Background(), destination)
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("hello-from-go!")); err != nil {
		panic(err)
	}
	response := make([]byte, len("reply-from-rust"))
	if _, err := io.ReadFull(conn, response); err != nil {
		panic(err)
	}
	if string(response) != "reply-from-rust" {
		panic("unexpected response: " + string(response))
	}
}
