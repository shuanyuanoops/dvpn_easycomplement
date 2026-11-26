package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"log"

	"dvpn-sim/internal/chain"
	"dvpn-sim/internal/link"
	"dvpn-sim/internal/merkle"
)

func key() (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return pub, priv
}

func submit(c *chain.Chain, tx chain.Tx) {
	if err := c.Submit(tx); err != nil {
		log.Fatalf("submit %s: %v", tx.Type, err)
	}
}

func seal(c *chain.Chain) chain.Block {
	b, err := c.Seal()
	if err != nil {
		log.Fatalf("seal: %v", err)
	}
	return b
}

func main() {
	c := chain.New()
	_, client := key()
	_, entry := key()
	_, middle := key()
	_, exit := key()

	// Fund accounts.
	submit(c, chain.Sign(chain.Tx{Type: chain.TxDeposit, From: "client", Amount: 10000}, client))
	for _, n := range []string{"entry", "middle", "exit"} {
		priv := map[string]ed25519.PrivateKey{"entry": entry, "middle": middle, "exit": exit}[n]
		submit(c, chain.Sign(chain.Tx{Type: chain.TxDeposit, From: n, Amount: 1000}, priv))
	}
	seal(c)

	// Register nodes.
	for _, n := range []string{"entry", "middle", "exit"} {
		priv := map[string]ed25519.PrivateKey{"entry": entry, "middle": middle, "exit": exit}[n]
		submit(c, chain.Sign(chain.Tx{
			Type: chain.TxRegisterNode, From: n, Node: n,
			Amount: 1000, Price: 1,
			Endpoint: "127.0.0.1:1700" + n[:1], Region: "r1",
		}, priv))
	}
	seal(c)

	// Epoch 1 settlement: one dual-signed link receipt as the leaf.
	linkSenderPub, linkSenderPriv := key()
	linkReceiverPub, linkReceiverPriv := key()
	lr := link.Sign("s1", "middle", "exit", 10, 9, 600, 540, linkSenderPriv, linkReceiverPriv)
	leaf := link.Hash(lr)
	tree := merkle.Build([][32]byte{leaf})
	root := tree.Root()
	proof, err := tree.Proof(0)
	if err != nil {
		log.Fatal(err)
	}
	submit(c, chain.Sign(chain.Tx{Type: chain.TxSettle, From: "client", Node: "entry", Bytes: 1000, Epoch: 1, Root: root, Amount: 1000}, client))
	submit(c, chain.Sign(chain.Tx{Type: chain.TxSettle, From: "client", Node: "middle", Bytes: 800, Epoch: 1, Root: root, Amount: 800}, client))
	submit(c, chain.Sign(chain.Tx{Type: chain.TxSettle, From: "client", Node: "exit", Bytes: 600, Epoch: 1, Root: root, Amount: 600}, client))
	seal(c)

	// Dispute the exit for 400, with the dual-signed link receipt and Merkle proof.
	submit(c, chain.Sign(chain.Tx{
		Type: chain.TxDispute, From: "client", Node: "exit", Amount: 400, Epoch: 1,
		Index: 0, Leaf: leaf, Proof: proof,
		LinkSession: "s1", LinkFrom: "middle", LinkTo: "exit",
		SentPackets: 10, RecvPackets: 9, SentBytes: 600, RecvBytes: 540,
		SenderPub: linkSenderPub, ReceiverPub: linkReceiverPub,
		SenderSig: lr.SenderSig, ReceiverSig: lr.ReceiverSig,
	}, client))
	seal(c)

	fmt.Println("=== chain ===")
	for _, b := range c.Blocks {
		fmt.Printf("block %d txs=%d hash=%x\n", b.Height, len(b.Txs), b.Hash[:6])
	}
	fmt.Println("=== accounts ===")
	for _, id := range []string{"client", "entry", "middle", "exit"} {
		a := c.Accounts[id]
		fmt.Printf("%-7s balance=%d locked=%d\n", id, a.Balance, a.Locked)
	}
	fmt.Println("=== nodes ===")
	for _, id := range []string{"entry", "middle", "exit"} {
		n := c.Nodes[id]
		fmt.Printf("%-7s stake=%d earned=%d active=%v\n", id, n.Stake, n.Earned, n.Active)
	}
	fmt.Printf("treasury=%d\n", c.Treasury)
	fmt.Println("=== on-chain vs off-chain ===")
	fmt.Println("on-chain : node registry, stake, epoch settlement (bytes + root), disputes/slash")
	fmt.Println("off-chain: payload, SNI, raw receipts, per-packet logs, client identity")
}
