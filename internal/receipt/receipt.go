package receipt

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Receipt is a signed statement of how many packets/bytes a process saw.
type Receipt struct {
	Name          string `json:"name"`
	Role          string `json:"role"` // client | entry | middle | exit | sink
	RunID         string `json:"run_id"`
	StartUnixNano int64  `json:"start_unix_nano"`
	EndUnixNano   int64  `json:"end_unix_nano"`
	Packets       int64  `json:"packets"`
	BytesIn       int64  `json:"bytes_in"`
	BytesOut      int64  `json:"bytes_out"`
	PubKey        []byte `json:"pub_key"`
	Sig           []byte `json:"sig"`
}

func New(name, role, runID string, start, end time.Time, packets, bytesIn, bytesOut int64, priv ed25519.PrivateKey) *Receipt {
	pub := priv.Public().(ed25519.PublicKey)
	r := &Receipt{
		Name:          name,
		Role:          role,
		RunID:         runID,
		StartUnixNano: start.UnixNano(),
		EndUnixNano:   end.UnixNano(),
		Packets:       packets,
		BytesIn:       bytesIn,
		BytesOut:      bytesOut,
		PubKey:        append([]byte(nil), pub...),
	}
	r.Sig = ed25519.Sign(priv, r.message())
	return r
}

func (r *Receipt) message() []byte {
	return []byte(fmt.Sprintf("%s|%s|%s|%d|%d|%d|%d|%d",
		r.Name, r.Role, r.RunID,
		r.StartUnixNano, r.EndUnixNano,
		r.Packets, r.BytesIn, r.BytesOut))
}

func (r *Receipt) Verify() bool {
	if len(r.PubKey) != ed25519.PublicKeySize || len(r.Sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(r.PubKey), r.message(), r.Sig)
}

func Write(path string, r *Receipt) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

func Read(path string) (*Receipt, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r Receipt
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	return &r, nil
}
