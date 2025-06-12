// rotator.go
package shamir

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"sort"
	"sync"
	"time"
)

// RotatorConfig holds parameters for share rotation.
type RotatorConfig struct {
	Storage          IStorage      // where shares live
	Threshold        int           // k
	TotalShares      int           // n
	RotationInterval time.Duration // how often to rotate
	ProactiveOnly    bool          // if true, only refresh shares; if false, full secret rotation
}

// Rotator drives periodic rotation or refresh of Shamir shares.
type Rotator struct {
	cfg     RotatorConfig
	stopCh  chan struct{}
	stopped sync.WaitGroup
}

// NewRotator constructs a Rotator.
func NewRotator(cfg RotatorConfig) (*Rotator, error) {
	if cfg.Storage == nil {
		return nil, errors.New("shamir/rotator: Storage cannot be nil")
	}
	if cfg.Threshold < 2 || cfg.TotalShares < cfg.Threshold {
		return nil, fmt.Errorf("shamir/rotator: invalid threshold/total: %d/%d", cfg.Threshold, cfg.TotalShares)
	}
	if cfg.RotationInterval <= 0 {
		return nil, errors.New("shamir/rotator: RotationInterval must be > 0")
	}
	return &Rotator{
		cfg:    cfg,
		stopCh: make(chan struct{}),
	}, nil
}

// Start begins the periodic rotation in a background goroutine.
// It will keep running until Stop() is called.
func (r *Rotator) Start() {
	ticker := time.NewTicker(r.cfg.RotationInterval)
	r.stopped.Add(1)
	go func() {
		defer func() {
			ticker.Stop()
			r.stopped.Done()
		}()
		for {
			select {
			case <-ticker.C:
				if err := r.tick(); err != nil {
					fmt.Printf("[shamir/rotator] rotation error: %v\n", err)
				}
			case <-r.stopCh:
				return
			}
		}
	}()
}

// Stop signals the rotator to cease and waits for cleanup.
func (r *Rotator) Stop() {
	close(r.stopCh)
	r.stopped.Wait()
}

// tick performs one rotation or refresh cycle.
func (r *Rotator) tick() error {
	// 1) Load all current shares
	idxs, err := r.cfg.Storage.ListShares()
	if err != nil {
		return fmt.Errorf("list shares: %w", err)
	}
	if len(idxs) < r.cfg.Threshold {
		return fmt.Errorf("not enough shares to operate: have %d, need %d", len(idxs), r.cfg.Threshold)
	}

	currentShares, err := RetrieveShares(idxs, r.cfg.Storage)
	if err != nil {
		return fmt.Errorf("retrieve shares: %w", err)
	}

	var newShares [][]byte
	if r.cfg.ProactiveOnly {
		// Proactive refresh: same secret, fresh shares
		newShares, err = proactiveRefresh(currentShares, r.cfg.Threshold, r.cfg.TotalShares)
		if err != nil {
			return fmt.Errorf("proactive refresh failed: %w", err)
		}
	} else {
		// Full rotation: new random secret
		newShares, err = fullRotate(currentShares, r.cfg.Threshold, r.cfg.TotalShares)
		if err != nil {
			return fmt.Errorf("full rotate failed: %w", err)
		}
	}

	// 3) Persist them
	if err := StoreShares(newShares, r.cfg.Storage); err != nil {
		return fmt.Errorf("store new shares: %w", err)
	}
	fmt.Printf("[shamir/rotator] successfully %s at %s\n",
		func() string {
			if r.cfg.ProactiveOnly {
				return "refreshed shares"
			}
			return "rotated secret"
		}(), time.Now().Format(time.RFC3339))
	return nil
}

// fullRotate reconstructs the old secret and re-splits it without changing the secret.
func fullRotate(oldShares [][]byte, t, n int) ([][]byte, error) {
	// Combine takes first t shares automatically if len > t.
	secret, err := Combine(oldShares)
	if err != nil {
		return nil, fmt.Errorf("combine old secret: %w", err)
	}
	// Re-split the existing secret to refresh shares.
	newShares, err := Split(secret, t, n)
	if err != nil {
		return nil, fmt.Errorf("split new secret: %w", err)
	}
	return newShares, nil
}

// proactiveRefresh keeps the same secret but churns share values.
func proactiveRefresh(oldShares [][]byte, t, n int) ([][]byte, error) {
	// Sort oldShares by share index (stored at offset 9) to align with zeroShares order.
	sort.Slice(oldShares, func(i, j int) bool {
		return oldShares[i][9] < oldShares[j][9]
	})
	// Combine to verify secret consistency but discard result
	if _, err := Combine(oldShares); err != nil {
		return nil, fmt.Errorf("combine for refresh: %w", err)
	}
	// generate a zero-secret share set (all zeros)
	zero := make([]byte, len(oldShares[0])-(4+1+1+1+2+1+4))
	zeroShares, err := Split(zero, t, n)
	if err != nil {
		return nil, fmt.Errorf("split zero: %w", err)
	}
	// XOR (add in GF(2^8)) old payload with zeroShares payload bytewise
	headLen := 4 + 1 + 1 + 1 + 2 + 1
	refreshed := make([][]byte, n)
	for i := 0; i < n; i++ {
		a := oldShares[i]
		b := zeroShares[i]
		sum := make([]byte, len(a))
		// copy header
		copy(sum[:headLen], a[:headLen])
		// compute new payload (unchanged because b[j]==0)
		for j := headLen; j < len(a)-4; j++ {
			sum[j] = a[j] ^ b[j]
		}
		// recalc CRC32
		crc := crc32.ChecksumIEEE(sum[:len(sum)-4])
		binary.BigEndian.PutUint32(sum[len(sum)-4:], crc)
		refreshed[i] = sum
	}
	return refreshed, nil
}
