package frame

import "testing"

func TestRoundTrip(t *testing.T) {
	inner := []byte("hello onion")
	b, err := Encode(inner, 64, TypeForward, 0xdeadbeef, 42)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 64 {
		t.Fatalf("frame len=%d", len(b))
	}
	got, typ, tag, seq, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	if typ != TypeForward || tag != 0xdeadbeef || seq != 42 || string(got) != string(inner) {
		t.Fatalf("typ=%d tag=%x seq=%d got=%q", typ, tag, seq, got)
	}
}

func TestTooLarge(t *testing.T) {
	if _, err := Encode(make([]byte, 100), 64, TypeForward, 1, 1); err == nil {
		t.Fatal("expected error")
	}
}

func TestReplyType(t *testing.T) {
	b, err := Encode([]byte("x"), 32, TypeReply, 7, 9)
	if err != nil {
		t.Fatal(err)
	}
	_, typ, tag, seq, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	if typ != TypeReply || tag != 7 || seq != 9 {
		t.Fatalf("typ=%d tag=%d seq=%d", typ, tag, seq)
	}
}
