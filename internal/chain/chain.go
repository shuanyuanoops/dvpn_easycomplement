package chain

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"

	"dvpn-sim/internal/link"
	"dvpn-sim/internal/merkle"
)

const MinStake = 100

const (
	TxRegisterNode = "register_node"
	TxStake        = "stake"
	TxUnstake      = "unstake"
	TxDeposit      = "deposit"
	TxSettle       = "settle"
	TxDispute      = "dispute"
	TxAdvanceEpoch = "advance_epoch"
)

type Tx struct {
	Type     string
	From     string
	Node     string
	Amount   int64
	Epoch    int64
	Bytes    int64
	Price    int64
	Endpoint string
	Region   string
	Root     [32]byte
	Index    int
	Leaf     [32]byte
	Proof    [][32]byte
	PubKey   []byte
	Sig      []byte
	Nonce    uint64

	LinkSession string
	LinkFrom    string
	LinkTo      string
	SentPackets int
	RecvPackets int
	SentBytes   int64
	RecvBytes   int64
	SenderPub   []byte
	ReceiverPub []byte
	SenderSig   []byte
	ReceiverSig []byte
}

func (tx Tx) message() []byte {
	return []byte(fmt.Sprintf("%s|%s|%s|%d|%d|%d|%d|%s|%s|%x|%d|%x|%s|%s|%s|%s|%d|%d|%d|%d|%x|%x|%x|%x|%d",
		tx.Type, tx.From, tx.Node, tx.Amount, tx.Epoch, tx.Bytes, tx.Price,
		tx.Endpoint, tx.Region, tx.Root, tx.Index, tx.Leaf, proofHex(tx.Proof),
		tx.LinkSession, tx.LinkFrom, tx.LinkTo, tx.SentPackets, tx.RecvPackets,
		tx.SentBytes, tx.RecvBytes, tx.SenderPub, tx.ReceiverPub, tx.SenderSig, tx.ReceiverSig, tx.Nonce))
}

func proofHex(p [][32]byte) string {
	out := ""
	for _, h := range p {
		out += fmt.Sprintf("%x", h)
	}
	return out
}

type Node struct {
	ID       string
	PubKey   []byte
	Endpoint string
	Region   string
	Price    int64
	Stake    int64
	Active   bool
	Earned   int64
}

type Account struct {
	Balance int64
	Locked  int64
	PubKey  []byte
	Nonce   uint64
}

type Block struct {
	Height int64
	Txs    []Tx
	Prev   [32]byte
	Hash   [32]byte
}

type Chain struct {
	Nodes         map[string]*Node
	Accounts      map[string]*Account
	Blocks        []Block
	Mempool       []Tx
	Treasury      int64
	Settlements   map[string]map[int64][32]byte
	CurrentEpoch  int64
	DisputeWindow int64
}

func New() *Chain {
	c := &Chain{
		Nodes:        map[string]*Node{},
		Accounts:     map[string]*Account{},
		Settlements:  map[string]map[int64][32]byte{},
		CurrentEpoch: 1,
	}
	genesis := Block{Height: 0}
	genesis.Hash = blockHash(genesis)
	c.Blocks = []Block{genesis}
	return c
}

func Sign(tx Tx, priv ed25519.PrivateKey) Tx {
	tx.PubKey = priv.Public().(ed25519.PublicKey)
	tx.Sig = ed25519.Sign(priv, tx.message())
	return tx
}

func (c *Chain) Submit(tx Tx) error {
	if len(tx.PubKey) != ed25519.PublicKeySize || len(tx.Sig) != ed25519.SignatureSize {
		return errors.New("bad key/signature size")
	}
	if !ed25519.Verify(tx.PubKey, tx.message(), tx.Sig) {
		return errors.New("bad signature")
	}
	c.Mempool = append(c.Mempool, tx)
	return nil
}

func (c *Chain) Seal() (Block, error) {
	prev := c.Blocks[len(c.Blocks)-1]
	b := Block{Height: prev.Height + 1, Prev: prev.Hash, Txs: c.Mempool}
	for _, tx := range b.Txs {
		if err := c.apply(tx); err != nil {
			return Block{}, fmt.Errorf("tx %s: %w", tx.Type, err)
		}
	}
	b.Hash = blockHash(b)
	c.Blocks = append(c.Blocks, b)
	c.Mempool = nil
	return b, nil
}

func (c *Chain) apply(tx Tx) error {
	acc := c.account(tx.From)
	if len(acc.PubKey) == 0 {
		if tx.Type != TxDeposit {
			return errors.New("account must deposit first")
		}
		acc.PubKey = append([]byte(nil), tx.PubKey...)
	} else if !bytes.Equal(acc.PubKey, tx.PubKey) {
		return errors.New("account key mismatch")
	}
	if tx.Nonce > 0 {
		if tx.Nonce != acc.Nonce+1 {
			return errors.New("bad nonce")
		}
		acc.Nonce = tx.Nonce
	}

	switch tx.Type {
	case TxDeposit:
		c.account(tx.From).Balance += tx.Amount

	case TxRegisterNode:
		if _, ok := c.Nodes[tx.Node]; ok {
			return errors.New("node exists")
		}
		if tx.Amount < MinStake {
			return errors.New("stake below minimum")
		}
		acc := c.account(tx.From)
		if acc.Balance < tx.Amount {
			return errors.New("insufficient balance")
		}
		acc.Balance -= tx.Amount
		c.Nodes[tx.Node] = &Node{
			ID:       tx.Node,
			PubKey:   append([]byte(nil), tx.PubKey...),
			Endpoint: tx.Endpoint,
			Region:   tx.Region,
			Price:    tx.Price,
			Stake:    tx.Amount,
			Active:   true,
		}

	case TxStake:
		n := c.Nodes[tx.Node]
		if n == nil {
			return errors.New("unknown node")
		}
		acc := c.account(tx.From)
		if acc.Balance < tx.Amount {
			return errors.New("insufficient balance")
		}
		acc.Balance -= tx.Amount
		n.Stake += tx.Amount

	case TxUnstake:
		n := c.Nodes[tx.Node]
		if n == nil {
			return errors.New("unknown node")
		}
		if n.Stake < tx.Amount {
			return errors.New("stake too low")
		}
		n.Stake -= tx.Amount
		c.account(tx.From).Balance += tx.Amount

	case TxSettle:
		n := c.Nodes[tx.Node]
		if n == nil || !n.Active {
			return errors.New("inactive node")
		}
		cost := tx.Bytes * n.Price
		if tx.Amount > 0 && cost > tx.Amount {
			return errors.New("settlement exceeds client cap")
		}
		acc := c.account(tx.From)
		if acc.Balance < cost {
			return errors.New("insufficient balance")
		}
		acc.Balance -= cost
		c.account(tx.Node).Balance += cost
		n.Earned += cost
		if c.Settlements[tx.Node] == nil {
			c.Settlements[tx.Node] = map[int64][32]byte{}
		}
		if _, exists := c.Settlements[tx.Node][tx.Epoch]; exists {
			return errors.New("epoch already settled")
		}
		c.Settlements[tx.Node][tx.Epoch] = tx.Root

	case TxDispute:
		n := c.Nodes[tx.Node]
		if n == nil {
			return errors.New("unknown node")
		}
		roots := c.Settlements[tx.Node]
		if roots == nil {
			return errors.New("no settlement for node")
		}
		root, ok := roots[tx.Epoch]
		if !ok {
			return errors.New("no settlement root for epoch")
		}
		lr := &link.Receipt{
			Session:     tx.LinkSession,
			From:        tx.LinkFrom,
			To:          tx.LinkTo,
			SentPackets: tx.SentPackets,
			RecvPackets: tx.RecvPackets,
			SentBytes:   tx.SentBytes,
			RecvBytes:   tx.RecvBytes,
			SenderSig:   tx.SenderSig,
			ReceiverSig: tx.ReceiverSig,
		}
		if link.Hash(lr) != tx.Leaf {
			return errors.New("leaf is not the link receipt")
		}
		if !lr.Verify(tx.SenderPub, tx.ReceiverPub) {
			return errors.New("bad link receipt signature")
		}
		if c.DisputeWindow > 0 && tx.Epoch < c.CurrentEpoch-c.DisputeWindow {
			return errors.New("dispute window expired")
		}
		if !merkle.Verify(root, tx.Leaf, tx.Index, tx.Proof) {
			return errors.New("invalid merkle proof")
		}
		slash := tx.Amount
		if slash > n.Stake {
			slash = n.Stake
		}
		n.Stake -= slash
		c.Treasury += slash
		if n.Stake == 0 {
			n.Active = false
		}

	case TxAdvanceEpoch:
		c.CurrentEpoch++

	default:
		return fmt.Errorf("unknown tx type %q", tx.Type)
	}
	return nil
}

func (c *Chain) account(id string) *Account {
	a := c.Accounts[id]
	if a == nil {
		a = &Account{}
		c.Accounts[id] = a
	}
	return a
}

func blockHash(b Block) [32]byte {
	h := sha256.New()
	fmt.Fprintf(h, "%d|%x|%d", b.Height, b.Prev, len(b.Txs))
	for _, tx := range b.Txs {
		h.Write(tx.message())
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
