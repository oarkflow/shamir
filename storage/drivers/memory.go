// storage/drivers/memory_storage.go
package drivers

import (
	"errors"
	"sync"
)

// MemoryStorage implements IStorage in memory.
type MemoryStorage struct {
	mu   sync.RWMutex
	data map[byte][]byte
}

// NewMemoryStorage creates a new in-memory storage.
func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{data: make(map[byte][]byte)}
}

func (ms *MemoryStorage) SetShare(index byte, share []byte) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	// store a copy to prevent external mutation
	c := make([]byte, len(share))
	copy(c, share)
	ms.data[index] = c
	return nil
}

func (ms *MemoryStorage) GetShare(index byte) ([]byte, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()
	share, ok := ms.data[index]
	if !ok {
		return nil, errors.New("memory: share not found")
	}
	// return a copy
	c := make([]byte, len(share))
	copy(c, share)
	return c, nil
}

func (ms *MemoryStorage) ListShares() ([]byte, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()
	indices := make([]byte, 0, len(ms.data))
	for idx := range ms.data {
		indices = append(indices, idx)
	}
	return indices, nil
}

func (ms *MemoryStorage) DeleteShare(index byte) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	if _, ok := ms.data[index]; !ok {
		return errors.New("memory: share not found")
	}
	delete(ms.data, index)
	return nil
}

func (ms *MemoryStorage) BatchSet(shares map[byte][]byte) error {
	for idx, s := range shares {
		if err := ms.SetShare(idx, s); err != nil {
			return err
		}
	}
	return nil
}
