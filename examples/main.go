// main.go
package main

import (
	"fmt"

	"github.com/oarkflow/shamir"
	"github.com/oarkflow/shamir/storage"
	"github.com/oarkflow/shamir/storage/drivers"
)

func main() {
	fmt.Println("Shamir's Secret Sharing Example")

	splitCombine()
	splitStorage()
}

func splitCombine() {
	secret := []byte("Top Secret Message")
	threshold, total := 3, 5

	shares, err := shamir.Split(secret, threshold, total)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Generated %d shares (threshold %d):\n", total, threshold)
	for _, s := range shares {
		fmt.Printf(" • #%d → %x\n", s[9], s[10:]) // skip header bytes
	}

	recovered, err := shamir.Combine(shares)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Recovered: %s\n\n", string(recovered))
}

func splitStorage() {
	secret := []byte("Another Secret")
	threshold, total := 3, 5

	shares, err := shamir.Split(secret, threshold, total)
	if err != nil {
		panic(err)
	}

	// Setup MultiStorage with mixed backends
	ms := storage.NewMultiStorage()
	mem := drivers.NewMemoryStorage()
	file, err := drivers.NewFileStorage("./shares")
	if err != nil {
		panic(err)
	}

	// Assign alternating backends
	for i, s := range shares {
		idx := s[9]
		if i%2 == 0 {
			ms.AssignStorage(idx, mem)
		} else {
			ms.AssignStorage(idx, file)
		}
	}

	// Store all shares
	if err := storage.StoreSharesMulti(shares, ms); err != nil {
		panic(err)
	}

	// List stored indices
	indices, _ := ms.ListShares()
	fmt.Printf("Stored share indices: %v\n", indices)

	// Retrieve any threshold shares
	sub := indices[:threshold]
	recs, err := storage.RetrieveSharesMulti(sub, ms)
	if err != nil {
		panic(err)
	}

	// Reconstruct
	secret2, err := shamir.Combine(recs)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Reconstructed from storage: %s\n", string(secret2))
}
