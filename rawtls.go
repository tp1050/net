// rawtls.go  —  MIT licence  —  proof-of-concept only
// Raw-byte tunnel inside kernel-TLS 1.3  (server or client)
package main

import (
	"encoding/binary"
	"encoding/hex"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"unsafe"

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
	// >>>  SAME 32-BYTE KEY ON BOTH SIDES  <<<
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
		listen = flag.String("listen", "", "server:  :443")
		remote = flag.String("remote", "", "client:  65.109.204.230:443")
		iface  = flag.String("iface", "tun0", "tun interface")
	)
	flag.Parse()

	if *listen == "" && *remote == "" {
		log.Fatal("use -listen (server) OR -remote (client)")
	}

	var err error
	if *listen != "" {
		// ----------  SERVER  ----------
		tun, err = createTUN(*iface)
		if err != nil {
			log.Fatalf("tun: %v", err)
		}
		ln, err := net.Listen("tcp", *listen)
		if err != nil {
			log.Fatalf("listen: %v", err)
		}
		log.Printf("server listening on %s", *listen)
		for {
			conn, err := ln.Accept()
			if err != nil {
				log.Print(err)
				continue
			}
			go tunnel(conn)
		}
	} else {
		// ----------  CLIENT  ----------
		tun, err = createTUN(*iface)
		if err != nil {
			log.Fatalf("tun: %v", err)
		}
		conn, err := net.Dial("tcp", *remote)
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