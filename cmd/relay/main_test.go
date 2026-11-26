package main

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"testing"

	"dvpn-sim/internal/model"
)

func mustAddr(t *testing.T, s string) *net.UDPAddr {
	t.Helper()
	a, err := net.ResolveUDPAddr("udp", s)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestRouterUsesRoutes(t *testing.T) {
	middle := mustAddr(t, "127.0.0.1:17103")
	rt := &router{routes: map[string]*net.UDPAddr{"middle-1": middle}}
	got, ok := rt.resolve(model.NodeID("middle-1"))
	if !ok || got.String() != middle.String() {
		t.Fatalf("resolve(middle-1) = %v, %v", got, ok)
	}
	if _, ok := rt.resolve(model.NodeID("middle-0")); ok {
		t.Fatal("route miss must drop the packet")
	}
}

func TestRouterLegacyFallback(t *testing.T) {
	fallback := mustAddr(t, "127.0.0.1:17002")
	rt := &router{nextID: "middle-0", nextAddr: fallback}
	if got, ok := rt.resolve(model.NodeID("middle-0")); !ok || got.String() != fallback.String() {
		t.Fatalf("legacy match = %v, %v", got, ok)
	}
	if _, ok := rt.resolve(model.NodeID("middle-1")); ok {
		t.Fatal("legacy next-hop mismatch must drop the packet")
	}
	if _, ok := (&router{}).resolve(model.NodeID("x")); ok {
		t.Fatal("router without routes or next-addr must drop the packet")
	}
}

func TestSplitHopKey(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	msg := make([]byte, hopFieldSize+len(key))
	copy(msg, "middle-1")
	copy(msg[hopFieldSize:], key)

	hop, gotKey, err := splitHopKey(msg, "")
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	if hop != model.NodeID("middle-1") {
		t.Fatalf("hop = %q", hop)
	}
	if !bytes.Equal(gotKey, key) {
		t.Fatal("session key mangled")
	}

	hop, gotKey, err = splitHopKey(key, model.NodeID("middle-0"))
	if err != nil || hop != model.NodeID("middle-0") || !bytes.Equal(gotKey, key) {
		t.Fatalf("legacy split = %q, %v, %v", hop, gotKey, err)
	}

	if _, _, err := splitHopKey(make([]byte, 7), ""); err == nil {
		t.Fatal("short handshake must be rejected")
	}
	if _, _, err := splitHopKey(make([]byte, hopFieldSize+32), ""); err == nil {
		t.Fatal("empty next hop must be rejected")
	}
}

func TestLoadRoutes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "routes.json")
	if err := os.WriteFile(path, []byte(`{"middle-1":"127.0.0.1:17104"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	routes, err := loadRoutes(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if routes["middle-1"].Port != 17104 {
		t.Fatalf("port = %d", routes["middle-1"].Port)
	}

	if err := os.WriteFile(path, []byte(`{"middle-1":"not-an-addr"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadRoutes(path); err == nil {
		t.Fatal("bad address must fail")
	}
	if err := os.WriteFile(path, []byte(`nope`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadRoutes(path); err == nil {
		t.Fatal("bad JSON must fail")
	}
}
