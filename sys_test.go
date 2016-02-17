package keyctl

import (
	"os"
	"testing"
)

func TestListKeyring(t *testing.T) {
	ring, err := UserSessionKeyring()
	if err != nil {
		t.Fatal(err)
	}

	keys, err := listKeys(keyId(ring.Id()))
	if err != nil {
		t.Fatal(err)
	}

	for _, k := range keys {
		t.Logf("id %v", k)
	}
}

func TestFSGID(t *testing.T) {
	gid, err := getfsgid()
	if err != nil {
		t.Fatal(err)
	}
	if int(gid) != os.Getegid() {
		t.Fatalf("getfsgid() returned unexpected results (%d!=%d)", gid, os.Getegid())
	}
	t.Logf("fsgid = %v\n", gid)
}
