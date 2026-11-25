package circuit

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"sync"
)

// FwdState is the per-circuit reverse-path state at one relay.
type FwdState struct {
	Prev   *net.UDPAddr
	OutTag uint64 // 0 for an exit
}

// State maps local incoming tags to the previous peer and the rewritten
// outgoing tag. Each relay only sees its own tags.
type State struct {
	mu  sync.Mutex
	in  map[uint64]*FwdState
	out map[uint64]uint64 // outTag -> inTag
}

func NewState() *State {
	return &State{
		in:  map[uint64]*FwdState{},
		out: map[uint64]uint64{},
	}
}

// Forward records/updates the forward direction and returns the state with
// the outgoing tag (0 for an exit).
func (s *State) Forward(inTag uint64, prev *net.UDPAddr, isExit bool) *FwdState {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st := s.in[inTag]; st != nil {
		st.Prev = prev
		return st
	}
	st := &FwdState{Prev: prev}
	if !isExit {
		for {
			t := randTag()
			if _, exists := s.out[t]; !exists {
				st.OutTag = t
				s.out[t] = inTag
				break
			}
		}
	}
	s.in[inTag] = st
	return st
}

// ReplyPeer maps a reply tag (local out tag, or the in tag at an exit) back to
// the previous peer and the tag to use on that link.
func (s *State) ReplyPeer(tag uint64, isExit bool) (*net.UDPAddr, uint64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if isExit {
		st := s.in[tag]
		if st == nil {
			return nil, 0, false
		}
		return st.Prev, tag, true
	}
	inTag, ok := s.out[tag]
	if !ok {
		return nil, 0, false
	}
	st := s.in[inTag]
	if st == nil {
		return nil, 0, false
	}
	return st.Prev, inTag, true
}

func randTag() uint64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return binary.BigEndian.Uint64(b[:])
}
