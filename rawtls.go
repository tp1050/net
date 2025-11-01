// rawtls.go  —  MIT licence  —  proof-of-concept only
// Raw-byte tunnel inside kernel-TLS 1.3  (server or client)
package main

import (
	"crypto/rand"
	"encoding/binary"
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
	if _, err := rand.Read(key[:]); err != nil {
		log.Fatalf("rand: %v", err)
	}
	log.Printf("symmetric key %x (save this on client side!)", key)
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
		// SERVER mode
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
		// CLIENT mode
		conn, err := net.Dial("tcp", *remote)
		if err != nil {
			log.Fatalf("dial: %v", err)
		}
		log.Printf("client connected to %s", *remote)
		tunnel(conn)
	}
}

/* ---------- framing ---------- */

func tunnel(conn net.Conn) {
	aead, _ := chacha20poly1305.NewX(key[:])
	var n int
	buf := make([]byte, MTU+RECORD_OVER)
	for {
		// read record length
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

/* ---------- TUN helper ---------- */

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

/* ---------- stub nonce ---------- */
func nonce(counter int) []byte {
	var n [24]byte
	binary.BigEndian.PutUint64(n[16:], uint64(counter))
	return n[:]
}