//go:build ignore

// A real Go Yuubinsya server used by the ignored Rust client/throughput
// interoperability test. The password is supplied by the test environment so
// this fixture never contains a production credential.
package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"

	"github.com/Asutorufa/doradus/pkg/net/netapi"
	http2 "github.com/Asutorufa/doradus/pkg/net/proxy/http2/v2"
	"github.com/Asutorufa/doradus/pkg/net/proxy/yuubinsya"
)

type packetListener struct {
	conn *net.UDPConn
}

func (p *packetListener) Packet(context.Context) (net.PacketConn, error) {
	return p.conn, nil
}

func (p *packetListener) Close() error {
	return p.conn.Close()
}

type echoHandler struct{}

func (echoHandler) HandleStream(stream *netapi.StreamMeta) {
	_, _ = io.Copy(stream.Src, stream.Src)
}

func (echoHandler) HandlePacket(packet *netapi.Packet) {
	payload := append([]byte(nil), packet.GetPayload()...)
	_, _ = packet.WriteBack(payload, packet.Src())
}

func (echoHandler) HandlePing(ping *netapi.PingMeta) {
	_ = ping.WriteBack(0, nil)
}

func main() {
	if len(os.Args) != 2 {
		panic("usage: yuubinsya_go_server <port>")
	}
	port, err := strconv.Atoi(os.Args[1])
	if err != nil {
		panic(err)
	}
	password := os.Getenv("DORADUS_TEST_PASSWORD")
	if password == "" {
		panic("DORADUS_TEST_PASSWORD is required")
	}

	tcp, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		panic(err)
	}
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port})
	if err != nil {
		_ = tcp.Close()
		panic(err)
	}
	listener := netapi.NewListener(tcp, &packetListener{conn: udp})
	h2Listener, err := http2.NewServer(http2.ServerConfig{}, listener)
	if err != nil {
		_ = listener.Close()
		panic(err)
	}
	server, err := yuubinsya.NewServer(
		yuubinsya.ServerConfig{Password: password, UDPCoalesce: true},
		h2Listener,
		echoHandler{},
	)
	if err != nil {
		_ = h2Listener.Close()
		panic(err)
	}
	defer server.Close()

	fmt.Printf("READY 127.0.0.1:%d\n", port)
	select {}
}
