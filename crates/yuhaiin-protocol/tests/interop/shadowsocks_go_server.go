package main

import (
	"fmt"
	"io"
	"net"
	"os"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocks/core"
)

func main() {
	listenAddress := os.Getenv("SHADOWSOCKS_LISTEN")
	readyPath := os.Getenv("SHADOWSOCKS_READY")
	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(readyPath, []byte(listener.Addr().String()), 0o600); err != nil {
		panic(err)
	}
	defer listener.Close()

	raw, err := listener.Accept()
	if err != nil {
		panic(err)
	}
	defer raw.Close()
	cipher, err := core.PickCipher("AEAD_AES_256_GCM", nil, "secret")
	if err != nil {
		panic(err)
	}
	conn := cipher.StreamConn(raw)
	if err := discardAddress(conn); err != nil {
		panic(err)
	}
	var request [4]byte
	if _, err := io.ReadFull(conn, request[:]); err != nil {
		panic(err)
	}
	if string(request[:]) != "ping" {
		panic("unexpected Shadowsocks payload")
	}
	if _, err := conn.Write([]byte("pong")); err != nil {
		panic(err)
	}
}

func discardAddress(r io.Reader) error {
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return err
	}
	switch atyp[0] {
	case 1:
		var rest [6]byte
		_, err := io.ReadFull(r, rest[:])
		return err
	case 4:
		var rest [18]byte
		_, err := io.ReadFull(r, rest[:])
		return err
	case 3:
		var length [1]byte
		if _, err := io.ReadFull(r, length[:]); err != nil {
			return err
		}
		rest := make([]byte, int(length[0])+2)
		_, err := io.ReadFull(r, rest)
		return err
	default:
		return fmt.Errorf("unknown SOCKS address type: %d", atyp[0])
	}
}
