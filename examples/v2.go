// main.go
package main

import (
	"fmt"
	"time"

	"github.com/oarkflow/shamir"
	"github.com/oarkflow/shamir/storage/drivers"
)

func demoMode(name string, proactive bool) {
	fmt.Printf("\n=== %s mode ===\n", name)

	// 1) Initial split & in-memory storage
	secret := []byte("🚀 Launch Code Alpha")
	thr, tot := 3, 5

	shares, err := shamir.Split(secret, thr, tot)
	if err != nil {
		panic(err)
	}
	store := drivers.NewMemoryStorage()
	if err := shamir.StoreShares(shares, store); err != nil {
		panic(err)
	}

	// 2) Configure & start the rotator
	mode := "Full-Rotate"
	if proactive {
		mode = "Proactive-Refresh"
	}
	cfg := shamir.RotatorConfig{
		Storage:          store,
		Threshold:        thr,
		TotalShares:      tot,
		RotationInterval: 3 * time.Second, // demo interval; for production, consider intervals like 90*24*time.Hour (90 days)
		ProactiveOnly:    proactive,
	}
	rot, err := shamir.NewRotator(cfg)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Starting rotator [%s] (interval=3s)\n", mode)
	rot.Start()

	// let it tick 3 times
	time.Sleep(10 * time.Second)
	rot.Stop()
	fmt.Println("Rotator stopped")

	// 3) Reconstruct what’s now in storage
	idxs, _ := store.ListShares()
	idxs = idxs[:thr]
	fresh, err := shamir.RetrieveShares(idxs, store)
	if err != nil {
		panic(err)
	}
	recovered, err := shamir.Combine(fresh)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Recovered secret: %s\n", string(recovered))
}

func main() {
	fmt.Println("🔐 Shamir + Rotator Demo")

	// Demo 1: Full-Rotate (secret changes each interval)
	demoMode("Full Rotate", false)

	// Demo 2: Proactive-Refresh (secret stays the same)
	demoMode("Proactive Refresh", true)
}
