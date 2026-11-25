package sim

import (
	"container/heap"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	mrand "math/rand"

	dvpnlink "dvpn-sim/internal/link"
	"dvpn-sim/internal/model"
	"dvpn-sim/internal/onion"
)

// Config controls one simulation run.
type Config struct {
	Seed              int64
	Clients           int
	NodesPerRole      int
	PacketsPerSession int
	Hops              int
	CellSize          int
	DNSSize           int
	DNSMode           string // "tunnel" (through the circuit) or "local" (leaks)

	LinkLatencyMs    int64
	LinkBandwidthBps int64

	AuditProb float64
	Epsilon   float64

	CheatNode         string
	CheatFactor       float64
	ClientCheatFactor float64
}

// Results is what the CLI prints.
type Results struct {
	Sessions       int
	Packets        int
	Delivered      int
	TotalBytes     int64 // billable payload bytes delivered
	WireBytes      int64 // cell bytes sent
	TotalLatencyNs int64
	DurationNs     int64

	Audits        int
	Flagged       int
	ClientFlagged int
	Slashed       float64
	CheatSessions int
	AuditedCheat  int
	DetectedCheat int

	DNSPackets    int
	LocalDNSLeaks int
	Hops          int

	LinkReceipts    int
	LinkFailed      int
	Challenges      int
	ChallengeFailed int
}

func (r Results) AvgLatencyMs() float64 {
	if r.Delivered == 0 {
		return 0
	}
	return float64(r.TotalLatencyNs) / float64(r.Delivered) / 1e6
}

func (r Results) ThroughputMBps() float64 {
	if r.DurationNs == 0 {
		return 0
	}
	return float64(r.TotalBytes) / (float64(r.DurationNs) / 1e9) / 1e6
}

func (r Results) DetectionRate() float64 {
	if r.AuditedCheat == 0 {
		return 0
	}
	return float64(r.DetectedCheat) / float64(r.AuditedCheat)
}

type event struct {
	at   int64
	kind int // 0 = send, 1 = arrive at hop, 2 = deliver to destination
	pkt  model.Packet
}

type eventHeap []event

func (h eventHeap) Len() int            { return len(h) }
func (h eventHeap) Less(i, j int) bool  { return h[i].at < h[j].at }
func (h eventHeap) Swap(i, j int)       { h[i], h[j] = h[j], h[i] }
func (h *eventHeap) Push(x interface{}) { *h = append(*h, x.(event)) }
func (h *eventHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[:n-1]
	return x
}

type link struct {
	latency   int64
	bandwidth int64
	nextFree  int64
}

type counter struct {
	packets int
	bytes   int64
}

type sessionState struct {
	circuit     *model.Circuit
	clientBytes int64
	packets     int
	delivered   int
	latencyNs   int64
}

type Sim struct {
	cfg Config
	rng *mrand.Rand

	nodes   map[model.NodeID]*model.Node
	entries []model.NodeID
	middles []model.NodeID
	exits   []model.NodeID
	keys    map[model.NodeID]ed25519.PrivateKey

	circuitKeys map[string]map[model.NodeID][]byte

	links  map[string]*link
	events eventHeap
	now    int64

	sessions map[string]*sessionState
	counters map[string]map[model.NodeID]*counter
	receipts map[string]map[model.NodeID]*model.Receipt

	linkReceipts []*dvpnlink.Receipt
	hashes       map[string]map[model.NodeID]map[int][32]byte

	packetID int
	res      Results
}

func New(cfg Config) *Sim {
	if cfg.CheatFactor == 0 {
		cfg.CheatFactor = 1
	}
	if cfg.ClientCheatFactor == 0 {
		cfg.ClientCheatFactor = 1
	}
	if cfg.Hops == 0 {
		cfg.Hops = 3
	}
	if cfg.Hops < 2 || cfg.Hops > 4 {
		cfg.Hops = 3
	}
	if cfg.CellSize == 0 {
		cfg.CellSize = 1024
	}
	if cfg.DNSSize == 0 {
		cfg.DNSSize = 200
	}
	if cfg.DNSMode == "" {
		cfg.DNSMode = "tunnel"
	}
	s := &Sim{
		cfg:         cfg,
		rng:         mrand.New(mrand.NewSource(cfg.Seed)),
		nodes:       map[model.NodeID]*model.Node{},
		keys:        map[model.NodeID]ed25519.PrivateKey{},
		circuitKeys: map[string]map[model.NodeID][]byte{},
		links:       map[string]*link{},
		sessions:    map[string]*sessionState{},
		counters:    map[string]map[model.NodeID]*counter{},
		receipts:    map[string]map[model.NodeID]*model.Receipt{},
		hashes:      map[string]map[model.NodeID]map[int][32]byte{},
	}
	heap.Init(&s.events)
	s.initNodes()
	return s
}

func (s *Sim) initNodes() {
	roles := []model.Role{model.RoleEntry, model.RoleMiddle, model.RoleExit}
	for i := 0; i < s.cfg.NodesPerRole; i++ {
		for _, role := range roles {
			id := model.NodeID(fmt.Sprintf("%s-%d", role, i))
			_, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				panic(err)
			}
			n := &model.Node{
				ID:       id,
				Role:     role,
				Operator: fmt.Sprintf("op-%s-%d", role, i),
				Region:   "r1",
				Stake:    100,
			}
			s.nodes[id] = n
			s.keys[id] = priv
			switch role {
			case model.RoleEntry:
				s.entries = append(s.entries, id)
			case model.RoleMiddle:
				s.middles = append(s.middles, id)
			case model.RoleExit:
				s.exits = append(s.exits, id)
			}
		}
	}
}

func (s *Sim) pick(pool []model.NodeID, usedOperators map[string]bool) model.NodeID {
	for attempt := 0; attempt < 100; attempt++ {
		id := pool[s.rng.Intn(len(pool))]
		if !usedOperators[s.nodes[id].Operator] {
			return id
		}
	}
	return pool[s.rng.Intn(len(pool))]
}

func (s *Sim) buildCircuit(client string) *model.Circuit {
	used := map[string]bool{}
	e := s.pick(s.entries, used)
	used[s.nodes[e].Operator] = true
	x := s.pick(s.exits, used)
	used[s.nodes[x].Operator] = true

	nodes := []model.NodeID{e}
	switch s.cfg.Hops {
	case 2:
		// entry -> exit
	case 3:
		m := s.pick(s.middles, used)
		used[s.nodes[m].Operator] = true
		nodes = append(nodes, m)
	case 4:
		m1 := s.pick(s.middles, used)
		used[s.nodes[m1].Operator] = true
		nodes = append(nodes, m1)
		m2 := s.pick(s.middles, used)
		used[s.nodes[m2].Operator] = true
		nodes = append(nodes, m2)
	}
	nodes = append(nodes, x)

	circ := &model.Circuit{ID: "circuit-" + client, Client: client, Nodes: nodes}
	keys := map[model.NodeID][]byte{}
	for _, id := range circ.Path() {
		k := make([]byte, 32)
		if _, err := rand.Read(k); err != nil {
			panic(err)
		}
		keys[id] = k
	}
	s.circuitKeys[circ.ID] = keys
	return circ
}

func (s *Sim) push(kind int, at int64, pkt model.Packet) {
	heap.Push(&s.events, event{at: at, kind: kind, pkt: pkt})
}

func (s *Sim) Run() Results {
	s.res.Sessions = s.cfg.Clients
	s.res.Hops = s.cfg.Hops
	for c := 0; c < s.cfg.Clients; c++ {
		client := fmt.Sprintf("client-%d", c)
		circ := s.buildCircuit(client)
		s.sessions[client] = &sessionState{circuit: circ}
		base := int64(c) * 1_000_000

		if s.cfg.DNSMode == "local" {
			s.res.LocalDNSLeaks++
		} else {
			at := base - 1_000_000
			if at < 0 {
				at = 0
			}
			s.push(0, at, model.Packet{
				ID:          s.packetID,
				Session:     client,
				Kind:        "dns",
				Seq:         -1,
				PayloadSize: s.cfg.DNSSize,
				Path:        circ.Path(),
			})
			s.packetID++
			s.res.DNSPackets++
		}

		for p := 0; p < s.cfg.PacketsPerSession; p++ {
			s.push(0, base+int64(p)*1_000_000, model.Packet{
				ID:      s.packetID,
				Session: client,
				Kind:    "data",
				Seq:     p,
				Path:    circ.Path(),
			})
			s.packetID++
		}
	}

	for s.events.Len() > 0 {
		ev := heap.Pop(&s.events).(event)
		s.now = ev.at
		switch ev.kind {
		case 0:
			s.handleSend(ev.pkt)
		case 1:
			s.handleArrive(ev.pkt)
		case 2:
			s.handleDeliver(ev.pkt)
		}
	}

	s.res.DurationNs = s.now
	s.buildReceipts()
	s.audit()
	return s.res
}

func (s *Sim) handleSend(pkt model.Packet) {
	ss := s.sessions[pkt.Session]
	if pkt.PayloadSize == 0 {
		pkt.PayloadSize = onion.Capacity(s.cfg.CellSize, len(pkt.Path))
	}
	payload := make([]byte, pkt.PayloadSize)
	cell, err := onion.Build(pkt.Path, payload, s.circuitKeys[ss.circuit.ID], s.cfg.CellSize)
	if err != nil {
		panic(fmt.Sprintf("build onion: %v", err))
	}

	ss.packets++
	reported := int64(float64(pkt.PayloadSize) * s.cfg.ClientCheatFactor)
	ss.clientBytes += reported
	s.res.Packets++
	s.res.WireBytes += int64(len(cell))

	pkt.Cell = cell
	pkt.Size = len(cell)
	pkt.SentAt = s.now
	pkt.Hop = 0
	delay := s.linkDelay("client", pkt.Path[0], pkt.Size)
	s.push(1, s.now+delay, pkt)
}

func (s *Sim) handleArrive(pkt model.Packet) {
	ss := s.sessions[pkt.Session]
	node := pkt.Path[pkt.Hop]
	next, inner, err := onion.Peel(pkt.Cell, s.circuitKeys[ss.circuit.ID][node])
	if err != nil {
		panic(fmt.Sprintf("peel %s: %v", node, err))
	}
	s.record(pkt.Session, node, int64(pkt.PayloadSize))
	s.remember(pkt)

	if next == "dest" {
		delay := s.linkDelay(node, "dest", pkt.Size)
		s.push(2, s.now+delay, pkt)
		return
	}
	if pkt.Hop+1 >= len(pkt.Path) || next != pkt.Path[pkt.Hop+1] {
		panic(fmt.Sprintf("onion next=%s, path next=%v", next, pkt.Path))
	}
	pkt.Cell = inner
	pkt.Hop++
	delay := s.linkDelay(node, next, pkt.Size)
	s.push(1, s.now+delay, pkt)
}

func (s *Sim) handleDeliver(pkt model.Packet) {
	s.res.Delivered++
	s.res.TotalBytes += int64(pkt.PayloadSize)
	s.res.TotalLatencyNs += s.now - pkt.SentAt
	ss := s.sessions[pkt.Session]
	ss.delivered++
	ss.latencyNs += s.now - pkt.SentAt
}

func (s *Sim) linkDelay(from, to model.NodeID, size int) int64 {
	key := string(from) + "->" + string(to)
	l := s.links[key]
	if l == nil {
		l = &link{latency: s.cfg.LinkLatencyMs * 1_000_000, bandwidth: s.cfg.LinkBandwidthBps}
		s.links[key] = l
	}
	start := s.now
	if l.nextFree > start {
		start = l.nextFree
	}
	serial := int64(size) * 1_000_000_000 / l.bandwidth
	if serial == 0 {
		serial = 1
	}
	l.nextFree = start + serial
	return start + serial + l.latency - s.now
}

func (s *Sim) record(session string, hop model.NodeID, bytes int64) {
	if s.cfg.CheatNode != "" && string(hop) == s.cfg.CheatNode {
		bytes = int64(float64(bytes) * s.cfg.CheatFactor)
	}
	m := s.counters[session]
	if m == nil {
		m = map[model.NodeID]*counter{}
		s.counters[session] = m
	}
	c := m[hop]
	if c == nil {
		c = &counter{}
		m[hop] = c
	}
	c.packets++
	c.bytes += bytes
}

func (s *Sim) remember(pkt model.Packet) {
	if pkt.Seq < 0 {
		return
	}
	m := s.hashes[pkt.Session]
	if m == nil {
		m = map[model.NodeID]map[int][32]byte{}
		s.hashes[pkt.Session] = m
	}
	node := pkt.Path[pkt.Hop]
	hm := m[node]
	if hm == nil {
		hm = map[int][32]byte{}
		m[node] = hm
	}
	hm[pkt.Seq] = dvpnlink.PacketHash(pkt.Session, pkt.Seq, int64(pkt.PayloadSize))
}

func (s *Sim) buildReceipts() {
	for session, ss := range s.sessions {
		s.receipts[session] = map[model.NodeID]*model.Receipt{}
		var prev [32]byte
		for _, hop := range ss.circuit.Path() {
			c := s.counters[session][hop]
			if c == nil {
				c = &counter{}
			}
			buf := make([]byte, 0, 32+len(session)+len(hop)+24)
			buf = append(buf, prev[:]...)
			buf = append(buf, []byte(fmt.Sprintf("%s|%s|%d", session, hop, c.bytes))...)
			h := sha256.Sum256(buf)
			sig := ed25519.Sign(s.keys[hop], h[:])
			s.receipts[session][hop] = &model.Receipt{
				Session:      session,
				Hop:          hop,
				SeqStart:     1,
				SeqEnd:       c.packets,
				PayloadBytes: c.bytes,
				PrevHash:     prev,
				Hash:         h,
				Sig:          sig,
			}
			prev = h
		}
		path := ss.circuit.Path()
		for i := 0; i+1 < len(path); i++ {
			from, to := path[i], path[i+1]
			c := s.counters[session][from]
			if c == nil {
				continue
			}
			s.linkReceipts = append(s.linkReceipts, dvpnlink.Sign(session, string(from), string(to), 1, c.packets, c.bytes, s.keys[from], s.keys[to]))
		}
	}
}

func (s *Sim) isCheatSession(session string) bool {
	ss := s.sessions[session]
	if s.cfg.ClientCheatFactor != 1 {
		return true
	}
	if s.cfg.CheatNode == "" {
		return false
	}
	for _, hop := range ss.circuit.Path() {
		if string(hop) == s.cfg.CheatNode {
			return true
		}
	}
	return false
}

func (s *Sim) audit() {
	s.res.LinkReceipts = len(s.linkReceipts)
	for _, lr := range s.linkReceipts {
		fromPub := s.keys[model.NodeID(lr.From)].Public().(ed25519.PublicKey)
		toPub := s.keys[model.NodeID(lr.To)].Public().(ed25519.PublicKey)
		if !lr.Verify(fromPub, toPub) {
			s.res.LinkFailed++
			continue
		}
		c := s.counters[lr.Session][model.NodeID(lr.To)]
		if c == nil || lr.PayloadBytes != c.bytes {
			s.res.LinkFailed++
		}
	}
	for session, ss := range s.sessions {
		payloadSize := int64(onion.Capacity(s.cfg.CellSize, len(ss.circuit.Path())))
		if s.cfg.PacketsPerSession == 0 {
			continue
		}
		for k := 0; k < 3; k++ {
			seq := s.rng.Intn(s.cfg.PacketsPerSession)
			for _, hop := range ss.circuit.Path() {
				s.res.Challenges++
				ch := dvpnlink.NewChallenge(session, seq, payloadSize)
				if !ch.Check(s.hashes[session][hop]) {
					s.res.ChallengeFailed++
				}
			}
		}
	}
	for session, ss := range s.sessions {
		if s.isCheatSession(session) {
			s.res.CheatSessions++
		}
		if s.rng.Float64() > s.cfg.AuditProb {
			continue
		}
		s.res.Audits++
		if s.isCheatSession(session) {
			s.res.AuditedCheat++
		}

		vals := []int64{ss.clientBytes}
		for _, hop := range ss.circuit.Path() {
			c := s.counters[session][hop]
			if c == nil {
				c = &counter{}
			}
			vals = append(vals, c.bytes)
		}
		med := medianInt64(vals)
		if med == 0 {
			continue
		}

		flagged := false
		for _, hop := range ss.circuit.Path() {
			c := s.counters[session][hop]
			if c == nil {
				continue
			}
			diff := float64(c.bytes-med) / float64(med)
			if diff > s.cfg.Epsilon {
				flagged = true
				s.res.Slashed += s.nodes[hop].Stake * 0.1
			}
		}
		diffClient := float64(ss.clientBytes-med) / float64(med)
		if diffClient > s.cfg.Epsilon || diffClient < -s.cfg.Epsilon {
			flagged = true
			s.res.ClientFlagged++
		}
		if flagged {
			s.res.Flagged++
			if s.isCheatSession(session) {
				s.res.DetectedCheat++
			}
		}
	}
}

func medianInt64(v []int64) int64 {
	if len(v) == 0 {
		return 0
	}
	c := make([]int64, len(v))
	copy(c, v)
	for i := 1; i < len(c); i++ {
		for j := i; j > 0 && c[j] < c[j-1]; j-- {
			c[j], c[j-1] = c[j-1], c[j]
		}
	}
	return c[len(c)/2]
}
