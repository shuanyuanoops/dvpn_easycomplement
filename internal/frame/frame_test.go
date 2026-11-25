package frame

import "testing"

func TestRoundTrip(t *testing.T) {
	inner := []byte("hello onion")
	b, err := Encode(inner, 64)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 64 {
		t.Fatalf("frame len=%d", len(b))
	}
	got, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(inner) {
		t.Fatalf("got %q", got)
	}
}

func TestTooLarge(t *testing.T) {
	if _, err := Encode(make([]byte, 100), 64); err == nil {
		t.Fatal("expected error")
	}
}
