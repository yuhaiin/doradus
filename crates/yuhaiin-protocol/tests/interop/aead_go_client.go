package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/aead"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/fixed"
)

func main() {
	listen := os.Getenv("AEAD_LISTEN")
	if os.Getenv("AEAD_MODE") == "udp" {
		runUDP(newUDPParent(listen))
		return
	}

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
	proxy, err := aead.NewClient(aead.Config{
		Password:     "secret",
		CryptoMethod: aead.CryptoMethodXChacha20Poly1305,
	}, parent)
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

type udpParent struct {
	remote *net.UDPAddr
}

func newUDPParent(listen string) netapi.Proxy {
	remote, err := net.ResolveUDPAddr("udp", listen)
	if err != nil {
		panic(err)
	}
	return &udpParent{remote: remote}
}

func (p *udpParent) Conn(context.Context, netapi.Address) (net.Conn, error) {
	return nil, errors.New("UDP test parent does not provide streams")
}

func (p *udpParent) PacketConn(context.Context, netapi.Address) (net.PacketConn, error) {
	packet, err := net.ListenPacket("udp", "")
	if err != nil {
		return nil, err
	}
	return &udpFixedPacketConn{PacketConn: packet, remote: p.remote}, nil
}

func (p *udpParent) Ping(context.Context, netapi.Address) (uint64, error) {
	return 0, errors.New("UDP test parent does not provide ping")
}

func (p *udpParent) Dispatch(_ context.Context, address netapi.Address) (netapi.Address, error) {
	return address, nil
}

func (p *udpParent) Close() error { return nil }

type udpFixedPacketConn struct {
	net.PacketConn
	remote net.Addr
}

func (p *udpFixedPacketConn) WriteTo(payload []byte, _ net.Addr) (int, error) {
	return p.PacketConn.WriteTo(payload, p.remote)
}

func (p *udpFixedPacketConn) ReadFrom(payload []byte) (int, net.Addr, error) {
	n, _, err := p.PacketConn.ReadFrom(payload)
	return n, p.remote, err
}

func runUDP(parent netapi.Proxy) {
	proxy, err := aead.NewClient(aead.Config{
		Password:     "secret",
		CryptoMethod: aead.CryptoMethodXChacha20Poly1305,
	}, parent)
	if err != nil {
		panic(err)
	}
	target, err := netapi.ParseAddressPort("udp", "192.0.2.1", 53)
	if err != nil {
		panic(err)
	}
	packet, err := proxy.PacketConn(context.Background(), target)
	if err != nil {
		panic(err)
	}
	defer packet.Close()
	if _, err := packet.WriteTo([]byte("ping"), target); err != nil {
		panic(err)
	}
	response := make([]byte, 64)
	n, _, err := packet.ReadFrom(response)
	if err != nil {
		panic(err)
	}
	if string(response[:n]) != "pong" {
		panic(fmt.Sprintf("unexpected UDP response: %q", response[:n]))
	}
}
