package chain

import (
	"crypto/ed25519"
	"crypto/rand"
	"reflect"
	"strings"
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
	c.Submit(signed(Tx{Type: TxDeposit, From: "client", Amount: 10000, Nonce: 1}, clientPriv))
	c.Submit(signed(Tx{Type: TxDeposit, From: "node", Amount: 1000, Nonce: 1}, nodePriv))
	if _, err := c.Seal(); err != nil {
		t.Fatal(err)
	}

	c.Submit(signed(Tx{
		Type: TxRegisterNode, From: "node", Node: "node",
		Amount: 1000, Price: 1, Endpoint: "127.0.0.1:1", Region: "r1", Nonce: 2,
	}, nodePriv))
	if _, err := c.Seal(); err != nil {
		t.Fatal(err)
	}
	if c.Nodes["node"] == nil || !c.Nodes["node"].Active {
		t.Fatal("node not registered")
	}

	c.Submit(signed(Tx{Type: TxSettle, From: "client", Node: "node", Bytes: 500, Epoch: 1, Nonce: 2}, clientPriv))
	if _, err := c.Seal(); err != nil {
		t.Fatal(err)
	}
	if c.Accounts["client"].Balance != 9500 {
		t.Fatalf("client balance=%d", c.Accounts["client"].Balance)
	}
	if c.Accounts["node"].Balance != 500 {
		t.Fatalf("node balance=%d", c.Accounts["node"].Balance)
	}
	if c.Accounts["client"].Nonce != 2 || c.Accounts["node"].Nonce != 2 {
		t.Fatalf("client nonce=%d node nonce=%d", c.Accounts["client"].Nonce, c.Accounts["node"].Nonce)
	}
	_ = clientPub
	_ = nodePub
}

func TestDisputeSlashes(t *testing.T) {
	c := New()
	_, clientPriv := key(t)
	_, nodePriv := key(t)
	c.Submit(signed(Tx{Type: TxDeposit, From: "client", Amount: 10000, Nonce: 1}, clientPriv))
	c.Submit(signed(Tx{Type: TxDeposit, From: "node", Amount: 1000, Nonce: 1}, nodePriv))
	c.Seal()
	c.Submit(signed(Tx{Type: TxRegisterNode, From: "node", Node: "node", Amount: 1000, Price: 1, Nonce: 2}, nodePriv))
	c.Seal()
	linkSenderPub, linkSenderPriv := key(t)
	linkReceiverPub, linkReceiverPriv := key(t)
	lr := link.Sign("s1", "entry", "middle", 10, 9, 1000, 900, linkSenderPriv, linkReceiverPriv)
	leaf := link.Hash(lr)
	tree := merkle.Build([][32]byte{leaf})
	root := tree.Root()
	proof, _ := tree.Proof(0)
	c.Submit(signed(Tx{Type: TxSettle, From: "client", Node: "node", Bytes: 100, Epoch: 1, Root: root, Amount: 1000, Nonce: 2}, clientPriv))
	c.Seal()
	c.Submit(signed(Tx{
		Type: TxDispute, From: "client", Node: "node", Amount: 400, Epoch: 1, Nonce: 3,
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
	tx := signed(Tx{Type: TxDeposit, From: "a", Amount: 10, Nonce: 1}, priv)
	tx.Amount = 20
	if err := c.Submit(tx); err == nil {
		t.Fatal("tampered tx must fail")
	}
}

func TestBlocksChain(t *testing.T) {
	c := New()
	_, priv := key(t)
	c.Submit(signed(Tx{Type: TxDeposit, From: "a", Amount: 10, Nonce: 1}, priv))
	b1, err := c.Seal()
	if err != nil {
		t.Fatal(err)
	}
	c.Submit(signed(Tx{Type: TxDeposit, From: "a", Amount: 5, Nonce: 2}, priv))
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
	c.Submit(signed(Tx{Type: TxDeposit, From: "client", Amount: 10000, Nonce: 1}, clientPriv))
	c.Submit(signed(Tx{Type: TxDeposit, From: "node", Amount: 1000, Nonce: 1}, nodePriv))
	c.Seal()
	c.Submit(signed(Tx{Type: TxRegisterNode, From: "node", Node: "node", Amount: 1000, Price: 1, Nonce: 2}, nodePriv))
	c.Seal()
	c.Submit(signed(Tx{Type: TxSettle, From: "client", Node: "node", Bytes: 200, Epoch: 1, Amount: 100, Nonce: 2}, clientPriv))
	if _, err := c.Seal(); err == nil {
		t.Fatal("settle above cap must fail")
	}
}

func TestNonce(t *testing.T) {
	c := New()
	_, priv := key(t)
	c.Submit(signed(Tx{Type: TxDeposit, From: "a", Amount: 10, Nonce: 1}, priv))
	if _, err := c.Seal(); err != nil {
		t.Fatal(err)
	}
	c.Submit(signed(Tx{Type: TxDeposit, From: "a", Amount: 10, Nonce: 3}, priv))
	if _, err := c.Seal(); err == nil || !strings.Contains(err.Error(), "bad nonce") {
		t.Fatalf("bad nonce must fail, got %v", err)
	}
	if c.Accounts["a"].Nonce != 1 {
		t.Fatalf("failed tx must not advance nonce, got %d", c.Accounts["a"].Nonce)
	}
}

func TestNonceRequired(t *testing.T) {
	c := New()
	_, priv := key(t)
	c.Submit(signed(Tx{Type: TxDeposit, From: "a", Amount: 10}, priv))
	if _, err := c.Seal(); err == nil || !strings.Contains(err.Error(), "bad nonce") {
		t.Fatalf("missing nonce must fail, got %v", err)
	}
}

func TestNonceReplay(t *testing.T) {
	c := New()
	_, priv := key(t)
	c.Submit(signed(Tx{Type: TxDeposit, From: "a", Amount: 10, Nonce: 1}, priv))
	c.Seal()
	c.Submit(signed(Tx{Type: TxDeposit, From: "a", Amount: 10, Nonce: 2}, priv))
	c.Seal()
	// Replaying nonce 2 must be rejected while the account nonce stays 2.
	c.Submit(signed(Tx{Type: TxDeposit, From: "a", Amount: 10, Nonce: 2}, priv))
	if _, err := c.Seal(); err == nil || !strings.Contains(err.Error(), "bad nonce") {
		t.Fatalf("replayed nonce must fail, got %v", err)
	}
	if c.Accounts["a"].Nonce != 2 {
		t.Fatalf("failed tx must not advance nonce, got %d", c.Accounts["a"].Nonce)
	}
}

func TestSealAtomicOnBadNonce(t *testing.T) {
	c := New()
	_, clientPriv := key(t)
	_, nodePriv := key(t)

	// Create pre-existing state in earlier, successful blocks.
	c.Submit(signed(Tx{Type: TxDeposit, From: "client", Amount: 10000, Nonce: 1}, clientPriv))
	c.Submit(signed(Tx{Type: TxDeposit, From: "node", Amount: 1000, Nonce: 1}, nodePriv))
	if _, err := c.Seal(); err != nil {
		t.Fatal(err)
	}
	c.Submit(signed(Tx{Type: TxRegisterNode, From: "node", Node: "node", Amount: 1000, Price: 1, Nonce: 2}, nodePriv))
	if _, err := c.Seal(); err != nil {
		t.Fatal(err)
	}

	accountsBefore := copyAccounts(c.Accounts)
	nodesBefore := copyNodes(c.Nodes)
	blocksBefore := len(c.Blocks)
	treasuryBefore := c.Treasury

	// Failing block: a valid deposit from a fresh account (nonce 1, applied
	// first) followed by a tx with a bad nonce. Submit accepts both into the
	// mempool; the failure only happens while sealing.
	_, freshPriv := key(t)
	if err := c.Submit(signed(Tx{Type: TxDeposit, From: "fresh", Amount: 50, Nonce: 1}, freshPriv)); err != nil {
		t.Fatal(err)
	}
	if err := c.Submit(signed(Tx{Type: TxDeposit, From: "client", Amount: 500, Nonce: 9}, clientPriv)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Seal(); err == nil || !strings.Contains(err.Error(), "bad nonce") {
		t.Fatalf("seal must fail with bad nonce, got %v", err)
	}

	// Nothing may have changed, including the effects of the valid first tx.
	if got := copyAccounts(c.Accounts); !reflect.DeepEqual(got, accountsBefore) {
		t.Fatalf("accounts changed after failed seal:\nbefore=%+v\nafter=%+v", accountsBefore, got)
	}
	if got := copyNodes(c.Nodes); !reflect.DeepEqual(got, nodesBefore) {
		t.Fatalf("nodes changed after failed seal:\nbefore=%+v\nafter=%+v", nodesBefore, got)
	}
	if a := c.Accounts["client"]; a.Balance != 10000 || a.Nonce != 1 {
		t.Fatalf("client mutated: balance=%d nonce=%d", a.Balance, a.Nonce)
	}
	if _, ok := c.Accounts["fresh"]; ok {
		t.Fatal("partial account from failed block leaked")
	}
	if n := c.Nodes["node"]; n == nil || n.Stake != 1000 || !n.Active {
		t.Fatalf("node mutated: %+v", n)
	}
	if len(c.Blocks) != blocksBefore || c.Treasury != treasuryBefore {
		t.Fatalf("chain state changed: blocks=%d (want %d) treasury=%d (want %d)",
			len(c.Blocks), blocksBefore, c.Treasury, treasuryBefore)
	}
	if len(c.Mempool) != 2 {
		t.Fatalf("mempool must be kept for retry, got %d txs", len(c.Mempool))
	}

	// The retained mempool can be retried once the bad tx is dropped.
	c.Mempool = c.Mempool[:1]
	if err := c.Submit(signed(Tx{Type: TxDeposit, From: "client", Amount: 500, Nonce: 2}, clientPriv)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Seal(); err != nil {
		t.Fatalf("retry after failed seal: %v", err)
	}
	if a := c.Accounts["client"]; a.Balance != 10500 || a.Nonce != 2 {
		t.Fatalf("retried block not applied: balance=%d nonce=%d", a.Balance, a.Nonce)
	}
	if a := c.Accounts["fresh"]; a == nil || a.Balance != 50 || a.Nonce != 1 {
		t.Fatalf("fresh deposit not applied on retry: %+v", a)
	}
}

func TestSealAtomicKeepsSettlements(t *testing.T) {
	c := New()
	_, clientPriv := key(t)
	_, nodePriv := key(t)

	c.Submit(signed(Tx{Type: TxDeposit, From: "client", Amount: 10000, Nonce: 1}, clientPriv))
	c.Submit(signed(Tx{Type: TxDeposit, From: "node", Amount: 1000, Nonce: 1}, nodePriv))
	if _, err := c.Seal(); err != nil {
		t.Fatal(err)
	}
	c.Submit(signed(Tx{Type: TxRegisterNode, From: "node", Node: "node", Amount: 1000, Price: 1, Nonce: 2}, nodePriv))
	if _, err := c.Seal(); err != nil {
		t.Fatal(err)
	}

	// A valid settlement is applied first, then a bad-nonce tx fails: the
	// settlement, its nested map entry and the node earnings must all roll back.
	c.Submit(signed(Tx{
		Type: TxSettle, From: "client", Node: "node", Bytes: 100, Epoch: 1,
		Root: [32]byte{1}, Amount: 1000, Nonce: 2,
	}, clientPriv))
	c.Submit(signed(Tx{Type: TxDeposit, From: "client", Amount: 1, Nonce: 9}, clientPriv))
	if _, err := c.Seal(); err == nil || !strings.Contains(err.Error(), "bad nonce") {
		t.Fatalf("seal must fail with bad nonce, got %v", err)
	}

	if len(c.Settlements) != 0 {
		t.Fatalf("settlements leaked from failed block: %+v", c.Settlements)
	}
	if n := c.Nodes["node"]; n.Earned != 0 || n.Stake != 1000 {
		t.Fatalf("node rolled back incorrectly: earned=%d stake=%d", n.Earned, n.Stake)
	}
	if a := c.Accounts["client"]; a.Balance != 10000 || a.Nonce != 1 {
		t.Fatalf("client mutated: balance=%d nonce=%d", a.Balance, a.Nonce)
	}
	if a := c.Accounts["node"]; a.Balance != 0 || a.Nonce != 2 {
		t.Fatalf("node account mutated: balance=%d nonce=%d", a.Balance, a.Nonce)
	}
}

// copyAccounts and copyNodes capture comparable value copies so a test can
// assert that a failed Seal left the chain completely untouched.
func copyAccounts(accounts map[string]*Account) map[string]Account {
	out := make(map[string]Account, len(accounts))
	for id, a := range accounts {
		cp := *a
		cp.PubKey = append([]byte(nil), a.PubKey...)
		out[id] = cp
	}
	return out
}

func copyNodes(nodes map[string]*Node) map[string]Node {
	out := make(map[string]Node, len(nodes))
	for id, n := range nodes {
		cp := *n
		cp.PubKey = append([]byte(nil), n.PubKey...)
		out[id] = cp
	}
	return out
}

func TestDisputeWindow(t *testing.T) {
	c := New()
	_, clientPriv := key(t)
	_, nodePriv := key(t)
	c.DisputeWindow = 1
	c.Submit(signed(Tx{Type: TxDeposit, From: "client", Amount: 10000, Nonce: 1}, clientPriv))
	c.Submit(signed(Tx{Type: TxDeposit, From: "node", Amount: 1000, Nonce: 1}, nodePriv))
	c.Seal()
	c.Submit(signed(Tx{Type: TxRegisterNode, From: "node", Node: "node", Amount: 1000, Price: 1, Nonce: 2}, nodePriv))
	c.Seal()
	lr := link.Sign("s1", "entry", "middle", 10, 9, 1000, 900, keyPriv(t), keyPriv(t))
	leaf := link.Hash(lr)
	root := merkle.Build([][32]byte{leaf}).Root()
	c.Submit(signed(Tx{Type: TxSettle, From: "client", Node: "node", Bytes: 100, Epoch: 1, Root: root, Amount: 1000, Nonce: 2}, clientPriv))
	c.Seal()
	c.Submit(signed(Tx{Type: TxAdvanceEpoch, From: "client", Nonce: 3}, clientPriv))
	c.Seal()
	c.Submit(signed(Tx{Type: TxAdvanceEpoch, From: "client", Nonce: 4}, clientPriv))
	c.Seal()
	c.Submit(signed(Tx{Type: TxDispute, From: "client", Node: "node", Amount: 100, Epoch: 1, Nonce: 5}, clientPriv))
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
