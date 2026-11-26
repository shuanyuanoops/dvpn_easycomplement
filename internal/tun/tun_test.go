package tun

import (
	"bytes"
	"testing"
	"time"
)

func TestPump(t *testing.T) {
	src := NewPipe()
	dst := NewPipe()
	defer src.Close()
	defer dst.Close()
	go func() { _ = Pump(src, dst, 1500) }()

	pkt := []byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 1, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2}
	if _, err := src.Write(pkt); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1500)
	done := make(chan int, 1)
	go func() {
		n, _ := dst.Read(buf)
		done <- n
	}()
	select {
	case n := <-done:
		if n != len(pkt) || !bytes.Equal(buf[:n], pkt) {
			t.Fatalf("got %x want %x", buf[:n], pkt)
		}
	case <-time.After(time.Second):
		t.Fatal("pump timeout")
	}
}

func TestOpenTUN(t *testing.T) {
	d, err := Open("dvpn-test0")
	if err != nil {
		t.Skipf("tun unavailable: %v", err)
	}
	defer d.Close()
	if d.Name() == "" {
		t.Fatal("empty name")
	}
}
