package model

type NodeID string
type Role string

const (
	RoleEntry  Role = "entry"
	RoleMiddle Role = "middle"
	RoleExit   Role = "exit"
)

type Node struct {
	ID       NodeID
	Role     Role
	Operator string
	Region   string
	Stake    float64
}

type Circuit struct {
	ID     string
	Client string
	Nodes  []NodeID // entry ... exit
}

func (c *Circuit) Path() []NodeID { return c.Nodes }

type Packet struct {
	ID          int
	Seq         int
	Session     string
	Kind        string // "data" or "dns"
	Size        int    // wire bytes (cell size)
	PayloadSize int    // billable payload bytes
	Path        []NodeID
	Hop         int
	SentAt      int64 // ns, 0 until the client sends it
	Cell        []byte
}

type Receipt struct {
	Session      string
	Hop          NodeID
	SeqStart     int
	SeqEnd       int
	PayloadBytes int64
	PrevHash     [32]byte
	Hash         [32]byte
	Sig          []byte
}
