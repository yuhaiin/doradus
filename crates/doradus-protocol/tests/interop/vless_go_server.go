package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
)

var expectedUUID, _ = hex.DecodeString("00112233445566778899aabbccddeeff")

func main() {
	listener, err := net.Listen("tcp", os.Getenv("VLESS_LISTEN"))
	if err != nil {
		panic(err)
	}
	defer listener.Close()
	if err := os.WriteFile(os.Getenv("VLESS_READY"), []byte(listener.Addr().String()), 0o600); err != nil {
		panic(err)
	}
	raw, err := listener.Accept()
	if err != nil {
		panic(err)
	}
	defer raw.Close()
	if err := readRequest(raw); err != nil {
		panic(err)
	}
	if _, err := raw.Write([]byte{0, 0}); err != nil {
		panic(err)
	}
	var request [4]byte
	if _, err := io.ReadFull(raw, request[:]); err != nil {
		panic(err)
	}
	if string(request[:]) != "ping" {
		panic("unexpected VLESS payload")
	}
	if _, err := raw.Write([]byte("pong")); err != nil {
		panic(err)
	}
}

func readRequest(r io.Reader) error {
	var fixed [22]byte
	if _, err := io.ReadFull(r, fixed[:]); err != nil {
		return err
	}
	if fixed[0] != 0 || string(fixed[1:17]) != string(expectedUUID) || fixed[17] != 0 || fixed[18] != 1 {
		return fmt.Errorf("invalid VLESS request header")
	}
	var address []byte
	switch fixed[21] {
	case 1:
		address = make([]byte, 4)
	case 2:
		var length [1]byte
		if _, err := io.ReadFull(r, length[:]); err != nil {
			return err
		}
		address = make([]byte, int(length[0]))
	case 3:
		address = make([]byte, 16)
	default:
		return fmt.Errorf("unknown VLESS address type %d", fixed[21])
	}
	_, err := io.ReadFull(r, address)
	return err
}
