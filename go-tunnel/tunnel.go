package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/net/proxy"

	http_dialer "github.com/mwitkow/go-http-dialer"
)

const (
	TUNNEL_PORT     = 18000 // Port where the tunnel (in go or c) listens
	REAL_PROXY_PORT = 8080  // Port where the real proxy (cntlm) listens
	SO_ORIGINAL_DST = 80    // Socket option to get the original destination address
	TIMEOUT         = 5 * time.Second
)

// SockAddrIn is a struct to hold the sockaddr_in structure for IPv4 "retrieved" by the SO_ORIGINAL_DST.
type SockAddrIn struct {
	SinFamily uint16
	SinPort   [2]byte
	SinAddr   [4]byte
	// Pad to match the size of sockaddr_in
	Pad [8]byte
}

// helper function for getsockopt
func getsockopt(s int, level int, optname int, optval unsafe.Pointer, optlen *uint32) (err error) {
	_, _, e := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(s), uintptr(level), uintptr(optname), uintptr(optval), uintptr(unsafe.Pointer(optlen)), 0)
	if e != 0 {
		return e
	}
	return
}

// HTTP proxy request handler
func handleConnection(proxyDialer proxy.Dialer, conn net.Conn) {
	defer conn.Close()

	// Using RawConn is necessary to perform low-level operations on the underlying socket file descriptor in Go.
	// This allows us to use getsockopt to retrieve the original destination address set by the SO_ORIGINAL_DST option,
	// which isn't directly accessible through Go's higher-level networking API.
	rawConn, err := conn.(*net.TCPConn).SyscallConn()
	if err != nil {
		log.Printf("Failed to get raw connection: %v", err)
		return
	}

	var originalDst SockAddrIn
	// If Control is not nil, it is called after creating the network connection but before binding it to the operating system.
	rawConn.Control(func(fd uintptr) {
		optlen := uint32(unsafe.Sizeof(originalDst))
		// Retrieve the original destination address by making a syscall with the SO_ORIGINAL_DST option.
		err = getsockopt(int(fd), syscall.SOL_IP, SO_ORIGINAL_DST, unsafe.Pointer(&originalDst), &optlen)
		if err != nil {
			log.Printf("getsockopt SO_ORIGINAL_DST failed: %v", err)
		}
	})

	targetAddr := net.IPv4(originalDst.SinAddr[0], originalDst.SinAddr[1], originalDst.SinAddr[2], originalDst.SinAddr[3]).String()
	targetPort := (uint16(originalDst.SinPort[0]) << 8) | uint16(originalDst.SinPort[1])

	fmt.Printf("Original destination: %s:%d\n", targetAddr, targetPort)

	// Setup connection to original destination
	targetConn, err := proxyDialer.Dial("tcp", fmt.Sprintf("%s:%d", targetAddr, targetPort))
	if err != nil {
		log.Printf("Failed to connect to original destination: %v", err)
		return
	}
	defer targetConn.Close()

	fmt.Printf("Proxying connection from %s to %s\n", conn.RemoteAddr(), targetConn.RemoteAddr())

	// The following code creates two data transfer channels:
	// - From the client to the target server (handled by a separate goroutine).
	// - From the target server to the client (handled by the main goroutine).
	go func() {
		_, err = io.Copy(targetConn, conn)
		if err != nil {
			log.Printf("Failed copying data to target: %v", err)
		}
	}()
	_, err = io.Copy(conn, targetConn)
	if err != nil {
		log.Printf("Failed copying data from target: %v", err)
	}
}

func main() {
	// Start the proxy server on the localhost
	// We only demonstrate IPv4 in this example, but the same approach can be used for IPv6
	bpfProxyAddr := fmt.Sprintf("127.0.0.1:%d", TUNNEL_PORT)
	bpfListener, err := net.Listen("tcp", bpfProxyAddr)
	if err != nil {
		log.Fatalf("Failed to start proxy server: %v", err)
	}
	defer bpfListener.Close()

	realProxyAddr := fmt.Sprintf("http://127.0.0.1:%d", REAL_PROXY_PORT)
	realProxyUrl, err := url.Parse(realProxyAddr)
	if err != nil {
		log.Fatalf("Invalid proxy url: %v", err)
	}
	log.Printf("Using real proxy @ %s", realProxyAddr)
	proxyDialer := http_dialer.New(realProxyUrl, http_dialer.WithConnectionTimeout(TIMEOUT))
	if err != nil {
		log.Fatalf("Failed to get Dialer for real proxy: %v", err)
	}

	log.Printf("Proxy server with PID %d listening on %s", os.Getpid(), bpfProxyAddr)
	for {
		conn, err := bpfListener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		go handleConnection(proxyDialer, conn)
	}
}
