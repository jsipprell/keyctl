package keyctl

import (
	"math/rand"
	"testing"
	"time"
)

func helperRandBlock(sz int) []byte {
	b := make([]byte, 0, sz)

	for i := sz; i > 0; i = sz - len(b) {
		if i > 256 {
			i = 256
		}

		for _, v := range rand.Perm(i) {
			b = append(b, byte(v))
		}
	}

	return b
}

func helperCompareBlock(t *testing.T, name string, blk2 []byte, ring Keyring) {
	var (
		key *Key
		err error
	)
	if ring == nil {
		ring, err = SessionKeyring()
		if err != nil {
			t.Fatal(err)
		}
	}
	key, err = ring.Search(name)
	if err != nil {
		t.Fatal(err)
	}

	if err = key.ExpireAfter(5); err != nil {
		t.Fatal(err)
	}

	blk1, err := key.Get()
	if err != nil {
		t.Fatal(err)
	}

	helperCmp(t, blk1, blk2)
}

func helperCmp(t *testing.T, blk1 []byte, blk2 []byte) {
	if len(blk1) != len(blk2) {
		t.Fatalf("data block size mistmatch (%d!=%d)", len(blk1), len(blk2))
	}

	for i, j := range blk1 {
		if blk2[i] != j {
			t.Fatalf("data block inconsistency reading from key ring at position %d (%d!=%d)", i, j, blk2[j])
		}
	}
}

func TestRandomKey256(t *testing.T) {
	ring, err := SessionKeyring()
	if err != nil {
		t.Fatal(err)
	}
	r256 := helperRandBlock(256)
	id, err := ring.Add("rand256", r256)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("added %d byte random value key as: %v (%v)\n", len(r256), id.ID(), r256)
	helperCompareBlock(t, "rand256", r256, nil)
}

func TestRandomKey700(t *testing.T) {
	ring, err := SessionKeyring()
	if err != nil {
		t.Fatal(err)
	}

	r700 := helperRandBlock(700)
	id, err := ring.Add("rand700", r700)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("added %d byte random value key as: %v (%v)\n", len(r700), id.ID(), r700)
	helperCompareBlock(t, "rand700", r700, nil)
	time.Sleep(time.Duration(5)*time.Second + time.Duration(250000))

	if _, err = ring.Search("rand700"); err == nil {
		t.Fatal("'rand700' key did not expire in five seconds")
	}
	t.Logf("key %v expired after five seconds", id.ID())
}
