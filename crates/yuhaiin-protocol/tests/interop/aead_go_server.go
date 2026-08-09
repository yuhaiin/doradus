package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/aead"
)

func main() {
	if os.Getenv("AEAD_MODE") == "udp" {
		runUDP()
		return
	}

	listener, err := net.Listen("tcp", os.Getenv("AEAD_LISTEN"))
	if err != nil {
		panic(err)
	}
	defer listener.Close()
	if err := os.WriteFile(os.Getenv("AEAD_READY"), []byte(listener.Addr().String()), 0o600); err != nil {
		panic(err)
	}
	server, err := aead.NewServer(aead.Config{
		Password:     "secret",
		CryptoMethod: aead.CryptoMethodXChacha20Poly1305,
	}, netapi.NewListener(listener, nil))
	if err != nil {
		panic(err)
	}
	conn, err := server.Accept()
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	var request [4]byte
	if _, err := io.ReadFull(conn, request[:]); err != nil {
		panic(err)
	}
	if string(request[:]) != "ping" {
		panic(fmt.Sprintf("unexpected request: %q", request[:]))
	}
	if _, err := conn.Write([]byte("pong")); err != nil {
		panic(err)
	}
}

type packetProvider struct {
	packet net.PacketConn
}

func (p *packetProvider) Packet(context.Context) (net.PacketConn, error) {
	return p.packet, nil
}

func (p *packetProvider) Close() error { return p.packet.Close() }

func runUDP() {
	packet, err := net.ListenPacket("udp", os.Getenv("AEAD_LISTEN"))
	if err != nil {
		panic(err)
	}
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	base := netapi.NewListener(tcp, &packetProvider{packet: packet})
	server, err := aead.NewServer(aead.Config{
		Password:     "secret",
		CryptoMethod: aead.CryptoMethodXChacha20Poly1305,
	}, base)
	if err != nil {
		panic(err)
	}
	defer server.Close()
	conn, err := server.Packet(context.Background())
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	if err := os.WriteFile(os.Getenv("AEAD_READY"), []byte(packet.LocalAddr().String()), 0o600); err != nil {
		panic(err)
	}
	request := make([]byte, 64*1024)
	n, peer, err := conn.ReadFrom(request)
	if err != nil {
		panic(err)
	}
	if string(request[:n]) != "ping" {
		panic(fmt.Sprintf("unexpected UDP request: %q", request[:n]))
	}
	if _, err := conn.WriteTo([]byte("pong"), peer); err != nil {
		panic(err)
	}
}
