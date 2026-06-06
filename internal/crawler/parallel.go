package crawler

import (
	"sync"
)

// Semaphore is a counting semaphore backed by a buffered channel.
type Semaphore struct {
	ch chan struct{}
}

// NewSemaphore creates a semaphore with the given capacity.
func NewSemaphore(capacity int) *Semaphore {
	return &Semaphore{ch: make(chan struct{}, capacity)}
}

// Acquire blocks until a slot is available.
func (s *Semaphore) Acquire() {
	s.ch <- struct{}{}
}

// Release frees one slot.
func (s *Semaphore) Release() {
	<-s.ch
}

// HostSemaphores manages per-host semaphores with a global limit.
type HostSemaphores struct {
	mu         sync.Mutex
	hostSema   map[string]*Semaphore
	globalSema *Semaphore
	hostLimit  int
}

// NewHostSemaphores creates a semaphore manager with per-host and global limits.
func NewHostSemaphores(globalLimit, hostLimit int) *HostSemaphores {
	return &HostSemaphores{
		hostSema:   make(map[string]*Semaphore),
		globalSema: NewSemaphore(globalLimit),
		hostLimit:  hostLimit,
	}
}

// Acquire blocks until both global and per-host slots are available.
func (h *HostSemaphores) Acquire(host string) {
	h.globalSema.Acquire()

	h.mu.Lock()
	sem, ok := h.hostSema[host]
	if !ok {
		sem = NewSemaphore(h.hostLimit)
		h.hostSema[host] = sem
	}
	h.mu.Unlock()

	sem.Acquire()
}

// Release frees both per-host and global slots.
func (h *HostSemaphores) Release(host string) {
	h.mu.Lock()
	sem, ok := h.hostSema[host]
	h.mu.Unlock()

	if ok {
		sem.Release()
	}
	h.globalSema.Release()
}
