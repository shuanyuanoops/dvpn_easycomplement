package tun

import (
	"errors"
	"sync"
)

// Pipe is an in-memory Device used by tests and by the simulator.
type Pipe struct {
	mu     sync.Mutex
	ch     chan []byte
	closed bool
}

func NewPipe() *Pipe {
	return &Pipe{ch: make(chan []byte, 16)}
}

func (p *Pipe) Read(b []byte) (int, error) {
	pkt, ok := <-p.ch
	if !ok {
		return 0, errors.New("closed")
	}
	if len(pkt) > len(b) {
		return 0, errors.New("buffer too small")
	}
	return copy(b, pkt), nil
}

func (p *Pipe) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return 0, errors.New("closed")
	}
	pkt := append([]byte(nil), b...)
	select {
	case p.ch <- pkt:
		return len(b), nil
	default:
		return 0, errors.New("pipe full")
	}
}

func (p *Pipe) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.closed {
		p.closed = true
		close(p.ch)
	}
	return nil
}

func (p *Pipe) Name() string { return "pipe" }
