package frame

import "testing"

func TestRoundTrip(t *testing.T) {
	inner := []byte("hello onion")
	b, err := Encode(inner, 64, TypeForward, 0xdeadbeef)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 64 {
		t.Fatalf("frame len=%d", len(b))
	}
	got, typ, cid, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	if typ != TypeForward || cid != 0xdeadbeef || string(got) != string(inner) {
		t.Fatalf("typ=%d cid=%x got=%q", typ, cid, got)
	}
}

func TestTooLarge(t *testing.T) {
	if _, err := Encode(make([]byte, 100), 64, TypeForward, 1); err == nil {
		t.Fatal("expected error")
	}
}

func TestReplyType(t *testing.T) {
	b, err := Encode([]byte("x"), 32, TypeReply, 7)
	if err != nil {
		t.Fatal(err)
	}
	_, typ, cid, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	if typ != TypeReply || cid != 7 {
		t.Fatalf("typ=%d cid=%d", typ, cid)
	}
}
