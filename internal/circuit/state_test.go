package circuit

import (
	"net"
	"testing"
)

func addr(port int) *net.UDPAddr {
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port}
}

func TestEntryRewrite(t *testing.T) {
	s := NewState()
	client := addr(1000)
	st := s.Forward(10, client, false)
	if st.OutTag == 0 {
		t.Fatal("entry must allocate an out tag")
	}
	peer, tag, ok := s.ReplyPeer(st.OutTag, false)
	if !ok || tag != 10 || peer.Port != client.Port {
		t.Fatalf("reply ok=%v tag=%d peer=%v", ok, tag, peer)
	}
}

func TestExitRewrite(t *testing.T) {
	s := NewState()
	middle := addr(2000)
	st := s.Forward(20, middle, true)
	if st.OutTag != 0 {
		t.Fatal("exit must not allocate an out tag")
	}
	peer, tag, ok := s.ReplyPeer(20, true)
	if !ok || tag != 20 || peer.Port != middle.Port {
		t.Fatalf("reply ok=%v tag=%d peer=%v", ok, tag, peer)
	}
}

func TestUnknownTag(t *testing.T) {
	s := NewState()
	if _, _, ok := s.ReplyPeer(999, false); ok {
		t.Fatal("unknown tag must not resolve")
	}
	if _, _, ok := s.ReplyPeer(999, true); ok {
		t.Fatal("unknown exit tag must not resolve")
	}
}

func TestSameCircuitStableTag(t *testing.T) {
	s := NewState()
	st1 := s.Forward(30, addr(1), false)
	st2 := s.Forward(30, addr(1), false)
	if st1.OutTag != st2.OutTag {
		t.Fatal("same circuit must keep the same out tag")
	}
}
