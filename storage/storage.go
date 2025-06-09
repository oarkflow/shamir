// storage/storage.go
package storage

import (
	"errors"
	"sync"
)

// IStorage defines storage operations for shares.
type IStorage interface {
	SetShare(index byte, share []byte) error
	GetShare(index byte) ([]byte, error)
	ListShares() ([]byte, error)
	DeleteShare(index byte) error
	BatchSet(shares map[byte][]byte) error
}

// MultiStorage allows different storage backends per share index.
type MultiStorage struct {
	mu       sync.RWMutex
	backends map[byte]IStorage
}

// NewMultiStorage returns a new MultiStorage instance.
func NewMultiStorage() *MultiStorage {
	return &MultiStorage{backends: make(map[byte]IStorage)}
}

// AssignStorage assigns a specific storage backend for a share index.
func (ms *MultiStorage) AssignStorage(index byte, backend IStorage) {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	ms.backends[index] = backend
}

// SetShare stores a share in its designated storage backend.
func (ms *MultiStorage) SetShare(index byte, share []byte) error {
	ms.mu.RLock()
	backend, ok := ms.backends[index]
	ms.mu.RUnlock()
	if !ok {
		return errors.New("shamir: no storage backend assigned for share index")
	}
	return backend.SetShare(index, share)
}

// GetShare retrieves a share from its designated storage backend.
func (ms *MultiStorage) GetShare(index byte) ([]byte, error) {
	ms.mu.RLock()
	backend, ok := ms.backends[index]
	ms.mu.RUnlock()
	if !ok {
		return nil, errors.New("shamir: no storage backend assigned for share index")
	}
	return backend.GetShare(index)
}

// ListShares lists all share indices that have assigned backends.
func (ms *MultiStorage) ListShares() ([]byte, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()
	indices := make([]byte, 0, len(ms.backends))
	for idx := range ms.backends {
		indices = append(indices, idx)
	}
	return indices, nil
}

// DeleteShare deletes a share from its designated storage backend.
func (ms *MultiStorage) DeleteShare(index byte) error {
	ms.mu.RLock()
	backend, ok := ms.backends[index]
	ms.mu.RUnlock()
	if !ok {
		return errors.New("shamir: no storage backend assigned for share index")
	}
	return backend.DeleteShare(index)
}

// BatchSet stores multiple shares across potentially different backends.
func (ms *MultiStorage) BatchSet(shares map[byte][]byte) error {
	for idx, share := range shares {
		if err := ms.SetShare(idx, share); err != nil {
			return err
		}
	}
	return nil
}

// StoreSharesMulti is a convenience wrapper to store a slice of shares.
func StoreSharesMulti(shares [][]byte, ms *MultiStorage) error {
	batch := make(map[byte][]byte, len(shares))
	for _, s := range shares {
		if len(s) == 0 {
			continue
		}
		// Modified: Use share index from offset 9 instead of 0
		idx := s[9]
		batch[idx] = s
	}
	return ms.BatchSet(batch)
}

// RetrieveSharesMulti retrieves shares by index from the multi-storage.
func RetrieveSharesMulti(indices []byte, ms *MultiStorage) ([][]byte, error) {
	var out [][]byte
	for _, idx := range indices {
		s, err := ms.GetShare(idx)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}
