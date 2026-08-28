package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"time"

	websocket "github.com/Asutorufa/doradus/pkg/net/proxy/websocket/x"
)

var expectedUUID, _ = hex.DecodeString("00112233445566778899aabbccddeeff")

func main() {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	listener, err := net.Listen("tcp", os.Getenv("VLESS_TLS_LISTEN"))
	if err != nil {
		panic(err)
	}
	tlsListener := tls.NewListener(listener, &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS12,
	})
	defer tlsListener.Close()
	if err := os.WriteFile(os.Getenv("VLESS_TLS_READY"), []byte(tlsListener.Addr().String()), 0o600); err != nil {
		panic(err)
	}
	if os.Getenv("VLESS_TLS_WEBSOCKET") == "1" {
		serveWebSocket(tlsListener)
		return
	}
	conn, err := tlsListener.Accept()
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	if err := readRequest(conn); err != nil {
		panic(err)
	}
	if _, err := conn.Write([]byte{0, 0}); err != nil {
		panic(err)
	}
	var request [4]byte
	if _, err := io.ReadFull(conn, request[:]); err != nil {
		panic(err)
	}
	if string(request[:]) != "ping" {
		panic("unexpected VLESS payload")
	}
	if _, err := conn.Write([]byte("pong")); err != nil {
		panic(err)
	}
}

func serveWebSocket(listener net.Listener) {
	server := &http.Server{}
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/vless" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		conn, err := websocket.NewServerConn(w, req, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		if err := readRequest(conn); err != nil {
			panic(err)
		}
		if _, err := conn.Write([]byte{0, 0}); err != nil {
			panic(err)
		}
		var request [4]byte
		if _, err := io.ReadFull(conn, request[:]); err != nil {
			panic(err)
		}
		if string(request[:]) != "ping" {
			panic("unexpected VLESS payload")
		}
		if _, err := conn.Write([]byte("pong")); err != nil {
			panic(err)
		}
		go func() { _ = server.Shutdown(context.Background()) }()
	})
	if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
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
