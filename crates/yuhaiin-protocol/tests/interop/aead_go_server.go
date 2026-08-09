package main

import (
	"fmt"
	"io"
	"net"
	"os"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/aead"
)

func main() {
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
