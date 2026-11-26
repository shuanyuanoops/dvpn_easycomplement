package chain

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"dvpn-sim/internal/link"
	"dvpn-sim/internal/merkle"
)

func key(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func signed(tx Tx, priv ed25519.PrivateKey) Tx {
	tx.PubKey = priv.Public().(ed25519.PublicKey)
	tx.Sig = ed25519.Sign(priv, tx.message())
	return tx
}

func TestRegisterStakeSettle(t *testing.T) {
	c := New()
	clientPub, clientPriv := key(t)
	nodePub, nodePriv := key(t)

	// fund client and node
	c.Submit(signed(Tx{Type: TxDeposit, From: "client", Amount: 10000}, clientPriv))
	c.Submit(signed(Tx{Type: TxDeposit, From: "node", Amount: 1000}, nodePriv))
	if _, err := c.Seal(); err != nil {
		t.Fatal(err)
	}

	c.Submit(signed(Tx{
		Type: TxRegisterNode, From: "node", Node: "node",
		Amount: 1000, Price: 1, Endpoint: "127.0.0.1:1", Region: "r1",
	}, nodePriv))
	if _, err := c.Seal(); err != nil {
		t.Fatal(err)
	}
	if c.Nodes["node"] == nil || !c.Nodes["node"].Active {
		t.Fatal("node not registered")
	}

	c.Submit(signed(Tx{Type: TxSettle, From: "client", Node: "node", Bytes: 500, Epoch: 1}, clientPriv))
	if _, err := c.Seal(); err != nil {
		t.Fatal(err)
	}
	if c.Accounts["client"].Balance != 9500 {
		t.Fatalf("client balance=%d", c.Accounts["client"].Balance)
	}
	if c.Accounts["node"].Balance != 500 {
		t.Fatalf("node balance=%d", c.Accounts["node"].Balance)
	}
	_ = clientPub
	_ = nodePub
}

func TestDisputeSlashes(t *testing.T) {
	c := New()
	_, clientPriv := key(t)
	_, nodePriv := key(t)
	c.Submit(signed(Tx{Type: TxDeposit, From: "client", Amount: 10000}, clientPriv))
	c.Submit(signed(Tx{Type: TxDeposit, From: "node", Amount: 1000}, nodePriv))
	c.Seal()
	c.Submit(signed(Tx{Type: TxRegisterNode, From: "node", Node: "node", Amount: 1000, Price: 1}, nodePriv))
	c.Seal()
	linkSenderPub, linkSenderPriv := key(t)
	linkReceiverPub, linkReceiverPriv := key(t)
	lr := link.Sign("s1", "entry", "middle", 10, 9, 1000, 900, linkSenderPriv, linkReceiverPriv)
	leaf := link.Hash(lr)
	tree := merkle.Build([][32]byte{leaf})
	root := tree.Root()
	proof, _ := tree.Proof(0)
	c.Submit(signed(Tx{Type: TxSettle, From: "client", Node: "node", Bytes: 100, Epoch: 1, Root: root, Amount: 1000}, clientPriv))
	c.Seal()
	c.Submit(signed(Tx{
		Type: TxDispute, From: "client", Node: "node", Amount: 400, Epoch: 1,
		Index: 0, Leaf: leaf, Proof: proof,
		LinkSession: "s1", LinkFrom: "entry", LinkTo: "middle",
		SentPackets: 10, RecvPackets: 9, SentBytes: 1000, RecvBytes: 900,
		SenderPub: linkSenderPub, ReceiverPub: linkReceiverPub,
		SenderSig: lr.SenderSig, ReceiverSig: lr.ReceiverSig,
	}, clientPriv))
	c.Seal()
	if c.Nodes["node"].Stake != 600 {
		t.Fatalf("stake=%d", c.Nodes["node"].Stake)
	}
	if c.Treasury != 400 {
		t.Fatalf("treasury=%d", c.Treasury)
	}
}

func TestBadSignature(t *testing.T) {
	c := New()
	_, priv := key(t)
	tx := signed(Tx{Type: TxDeposit, From: "a", Amount: 10}, priv)
	tx.Amount = 20
	if err := c.Submit(tx); err == nil {
		t.Fatal("tampered tx must fail")
	}
}

func TestBlocksChain(t *testing.T) {
	c := New()
	_, priv := key(t)
	c.Submit(signed(Tx{Type: TxDeposit, From: "a", Amount: 10}, priv))
	b1, err := c.Seal()
	if err != nil {
		t.Fatal(err)
	}
	c.Submit(signed(Tx{Type: TxDeposit, From: "a", Amount: 5}, priv))
	b2, err := c.Seal()
	if err != nil {
		t.Fatal(err)
	}
	if b1.Prev != c.Blocks[0].Hash || b2.Prev != b1.Hash {
		t.Fatal("block chain broken")
	}
}

func TestSettleCap(t *testing.T) {
	c := New()
	_, clientPriv := key(t)
	_, nodePriv := key(t)
	c.Submit(signed(Tx{Type: TxDeposit, From: "client", Amount: 10000}, clientPriv))
	c.Submit(signed(Tx{Type: TxDeposit, From: "node", Amount: 1000}, nodePriv))
	c.Seal()
	c.Submit(signed(Tx{Type: TxRegisterNode, From: "node", Node: "node", Amount: 1000, Price: 1}, nodePriv))
	c.Seal()
	c.Submit(signed(Tx{Type: TxSettle, From: "client", Node: "node", Bytes: 200, Epoch: 1, Amount: 100}, clientPriv))
	if _, err := c.Seal(); err == nil {
		t.Fatal("settle above cap must fail")
	}
}

func TestNonce(t *testing.T) {
	c := New()
	_, priv := key(t)
	c.Submit(signed(Tx{Type: TxDeposit, From: "a", Amount: 10, Nonce: 1}, priv))
	c.Seal()
	c.Submit(signed(Tx{Type: TxDeposit, From: "a", Amount: 10, Nonce: 3}, priv))
	if _, err := c.Seal(); err == nil {
		t.Fatal("bad nonce must fail")
	}
}

func TestDisputeWindow(t *testing.T) {
	c := New()
	_, clientPriv := key(t)
	_, nodePriv := key(t)
	c.DisputeWindow = 1
	c.Submit(signed(Tx{Type: TxDeposit, From: "client", Amount: 10000}, clientPriv))
	c.Submit(signed(Tx{Type: TxDeposit, From: "node", Amount: 1000}, nodePriv))
	c.Seal()
	c.Submit(signed(Tx{Type: TxRegisterNode, From: "node", Node: "node", Amount: 1000, Price: 1}, nodePriv))
	c.Seal()
	lr := link.Sign("s1", "entry", "middle", 10, 9, 1000, 900, keyPriv(t), keyPriv(t))
	leaf := link.Hash(lr)
	root := merkle.Build([][32]byte{leaf}).Root()
	c.Submit(signed(Tx{Type: TxSettle, From: "client", Node: "node", Bytes: 100, Epoch: 1, Root: root, Amount: 1000}, clientPriv))
	c.Seal()
	c.Submit(signed(Tx{Type: TxAdvanceEpoch, From: "client"}, clientPriv))
	c.Seal()
	c.Submit(signed(Tx{Type: TxAdvanceEpoch, From: "client"}, clientPriv))
	c.Seal()
	c.Submit(signed(Tx{Type: TxDispute, From: "client", Node: "node", Amount: 100, Epoch: 1}, clientPriv))
	if _, err := c.Seal(); err == nil {
		t.Fatal("expired dispute window must fail")
	}
}

func keyPriv(t *testing.T) ed25519.PrivateKey {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}
