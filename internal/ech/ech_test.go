package ech

import (
	"bytes"
	"testing"
)

func TestGenerateShape(t *testing.T) {
	c, err := Generate("dvpn.local")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.List) < 4 || len(c.Server) < 4 {
		t.Fatal("short config")
	}
	if int(c.List[0])<<8|int(c.List[1]) != len(c.Server) {
		t.Fatal("list length mismatch")
	}
	if int(c.Server[2])<<8|int(c.Server[3]) != len(c.Server)-4 {
		t.Fatal("config length mismatch")
	}
	if !bytes.Contains(c.List, []byte("dvpn.local")) {
		t.Fatal("public name missing")
	}
}
