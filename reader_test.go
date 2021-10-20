package keyctl

import (
	"io"
	"testing"
)

func helperSetRandBlock(name string, sz int) (key ID, ring Keyring, blk []byte, err error) {
	if ring, err = SessionKeyring(); err != nil {
		return
	}

	blk = helperRandBlock(sz)
	if key, err = ring.Search(name); err != nil {
		key, err = ring.Add(name, blk)
		return
	}

	err = key.(*Key).Set(blk)
	return
}

func TestStreamReader(t *testing.T) {
	key, ring, blk, err := helperSetRandBlock("test1544bytestream", 719)

	if err != nil {
		t.Fatal(err)
	}

	r, err := OpenReader("test1544bytestream", ring)
	if err != nil {
		t.Fatal(err)
	}

	var i int
	buf := make([]byte, 128)
	for i, err = r.Read(buf); err == nil; i, err = r.Read(buf) {
		helperCmp(t, blk[:i], buf[:i])
		t.Logf("compared key %v %d bytes: %v", key.ID(), i, blk[:i])
		blk = blk[i:]
	}

	if err != io.EOF {
		t.Fatal(err)
	}

	if len(blk) != 0 {
		t.Fatalf("Read on key returned excess %d bytes", len(blk))
	}
}
