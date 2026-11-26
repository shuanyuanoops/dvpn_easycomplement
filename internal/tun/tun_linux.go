package tun

import (
	"errors"
	"os"
	"syscall"
	"unsafe"
)

const (
	tunSetIff = 0x400454ca
	iffTun    = 0x0001
	iffNoPI   = 0x1000
	ifNameSz  = 16
)

// Device is the minimal TUN surface used by the data plane.
type Device interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
	Name() string
}

// Native is a Linux TUN device. It carries raw IPv4/IPv6 packets.
type Native struct {
	f    *os.File
	name string
}

// Open creates/attaches a TUN device (requires CAP_NET_ADMIN or a user
// namespace with /dev/net/tun access). The IP/MTU/routes are configured by
// the caller (e.g. `ip addr add ... dev dvpn0`).
func Open(name string) (*Native, error) {
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	var ifr [40]byte
	copy(ifr[:ifNameSz], name)
	*(*uint16)(unsafe.Pointer(&ifr[ifNameSz])) = iffTun | iffNoPI
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), tunSetIff, uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		f.Close()
		return nil, errno
	}
	actual := ""
	for i := 0; i < ifNameSz; i++ {
		if ifr[i] == 0 {
			actual = string(ifr[:i])
			break
		}
	}
	if actual == "" {
		actual = name
	}
	_ = syscall.SetNonblock(int(f.Fd()), false)
	return &Native{f: f, name: actual}, nil
}

func (d *Native) Read(p []byte) (int, error) {
	return syscall.Read(int(d.f.Fd()), p)
}

func (d *Native) Write(p []byte) (int, error) {
	return syscall.Write(int(d.f.Fd()), p)
}
func (d *Native) Close() error { return d.f.Close() }
func (d *Native) Name() string { return d.name }

// Pump copies raw IP packets from src to dst until either side errors.
func Pump(src, dst Device, mtu int) error {
	if mtu <= 0 {
		return errors.New("bad mtu")
	}
	buf := make([]byte, mtu)
	for {
		n, err := src.Read(buf)
		if err != nil {
			return err
		}
		if n == 0 {
			continue
		}
		if _, err := dst.Write(buf[:n]); err != nil {
			return err
		}
	}
}
