// rawtls.go  —  MIT licence  —  proof-of-concept only
// Raw-byte tunnel inside kernel-TLS 1.3  (server or client)
package main
import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"time"
	"unsafe"

	"math/big" // Add this line

	chacha20poly1305 "golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/sys/unix"
)


const (
	MTU         = 65535
	RECORD_OVER = 4 + chacha20poly1305.Overhead // len field + AEAD tag
)

var (
	key [32]byte
	tun io.ReadWriter
)

func init() {
	// server key from 2025-11-01 21:44  (hex)
	src := "4ee965a03115fcfbd9fcbc5998e0dca9fd1447839806a26b728185f84646daf4"
	b, err := hex.DecodeString(src)
	if err != nil || len(b) != 32 {
		log.Fatalf("invalid key: %v", err)
	}
	copy(key[:], b)
	log.Printf("using server key %x", key)
}

func main() {
	var (
		listen = flag.String("listen", ":443", "TLS listen address")
		remote = flag.String("remote", "", "client mode: remote server ip:443")
		iface  = flag.String("iface", "tun0", "tun interface to use/create")
	)
	flag.Parse()

	var err error
	if *remote == "" {
		// ----------  SERVER  ----------
		tun, err = createTUN(*iface)
		if err != nil {
			log.Fatalf("tun: %v", err)
		}
		ln, err := tls.Listen("tcp", *listen, &tls.Config{
			Certificates: []tls.Certificate{mustLoadCert()}, // see helper below
			MinVersion:   tls.VersionTLS13,
		})
		if err != nil {
			log.Fatalf("tls listen: %v", err)
		}
		log.Printf("TLS server listening on %s", *listen)
		for {
			conn, err := ln.Accept()
			if err != nil {
				log.Print(err)
				continue
			}
			go tunnel(conn) // now speaks framing *inside* TLS
		}
	} else {
		// ----------  CLIENT  ----------
		tun, err = createTUN(*iface)
		if err != nil {
			log.Fatalf("tun: %v", err)
		}
		conn, err := tls.Dial("tcp", *remote, &tls.Config{
			InsecureSkipVerify: true, // self-signed cert
			MinVersion:         tls.VersionTLS13,
		})
		if err != nil {
			log.Fatalf("dial: %v", err)
		}
		log.Printf("client connected to %s", *remote)
		tunnel(conn)
	}
}

/* ----------  data plane  ---------- */

func tunnel(conn net.Conn) {
	aead, _ := chacha20poly1305.NewX(key[:])
	var n int
	buf := make([]byte, MTU+RECORD_OVER)
	for {
		// read 4-byte length
		if _, err := io.ReadFull(conn, buf[:4]); err != nil {
			return
		}
		ln := binary.BigEndian.Uint32(buf[:4])
		if ln > MTU {
			log.Printf("oversized record %d", ln)
			return
		}
		// read ciphertext
		if _, err := io.ReadFull(conn, buf[:ln]); err != nil {
			return
		}
		plain, err := aead.Open(buf[:0], nonce(n), buf[:ln], nil)
		if err != nil {
			log.Printf("decrypt fail: %v", err)
			return
		}
		n++
		if _, err = tun.Write(plain); err != nil {
			log.Printf("tun write: %v", err)
			return
		}
	}
}

/* ----------  TUN creator  ---------- */

func createTUN(name string) (io.ReadWriter, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	var ifr [unix.IFNAMSIZ + 64]byte
	copy(ifr[:], name)
	*(*uint16)(unsafe.Pointer(&ifr[unix.IFNAMSIZ])) = unix.IFF_TUN | unix.IFF_NO_PI
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.TUNSETIFF, uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		return nil, errno
	}
	return os.NewFile(uintptr(fd), name), nil
}

/* ----------  nonce helper  ---------- */
func nonce(counter int) []byte {
	var n [24]byte
	binary.BigEndian.PutUint64(n[16:], uint64(counter))
	return n[:]
}

/* ----------  self-signed cert helper  ---------- */
func mustLoadCert() tls.Certificate {
	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil { // not found → generate self-signed
		return generateSelfSigned()
	}
	return cert
}

func generateSelfSigned() tls.Certificate {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"*"}, // wildcard
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	privDER, _ := x509.MarshalECPrivateKey(priv)
	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}
}