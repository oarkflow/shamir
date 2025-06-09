// storage/drivers/file_storage.go
package drivers

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// FileStorage implements IStorage by writing each share to a file.
type FileStorage struct {
	dir string
	mu  sync.RWMutex
}

// NewFileStorage ensures the directory exists.
func NewFileStorage(dir string) (*FileStorage, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	return &FileStorage{dir: dir}, nil
}

func (fs *FileStorage) filePath(index byte) string {
	return filepath.Join(fs.dir, fmt.Sprintf("share_%d.dat", index))
}

func (fs *FileStorage) SetShare(index byte, share []byte) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return os.WriteFile(fs.filePath(index), share, 0600)
}

func (fs *FileStorage) GetShare(index byte) ([]byte, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	data, err := os.ReadFile(fs.filePath(index))
	if err != nil {
		return nil, errors.New("filestorage: share not found")
	}
	return data, nil
}

func (fs *FileStorage) ListShares() ([]byte, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	entries, err := os.ReadDir(fs.dir)
	if err != nil {
		return nil, err
	}
	var indices []byte
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "share_") || !strings.HasSuffix(name, ".dat") {
			continue
		}
		num := strings.TrimSuffix(strings.TrimPrefix(name, "share_"), ".dat")
		i, err := strconv.Atoi(num)
		if err != nil {
			continue
		}
		indices = append(indices, byte(i))
	}
	return indices, nil
}

func (fs *FileStorage) DeleteShare(index byte) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	path := fs.filePath(index)
	if err := os.Remove(path); err != nil {
		return errors.New("filestorage: share not found or could not delete")
	}
	return nil
}

func (fs *FileStorage) BatchSet(shares map[byte][]byte) error {
	for idx, s := range shares {
		if err := fs.SetShare(idx, s); err != nil {
			return err
		}
	}
	return nil
}
