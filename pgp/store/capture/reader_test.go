package capture

import (
	"os"
	"testing"

	"golang.org/x/crypto/openpgp"
)

const (
	testPacketFile      = "packets.gpg"
	testArmorPacketFile = "packets.asc"
)

func helperDumpPrivKeys(el openpgp.EntityList, reader *Reader, t *testing.T) {
	for _, ent := range el {
		id := ent.PrimaryKey.KeyId
		pk, ok := reader.PrivateKey(id)
		if !ok {
			t.Fatalf("no private key for %016x\n", id)
		}
		t.Logf("privkey %016x %#v\n", id, pk)
	}
}

func TestReader(t *testing.T) {
	f, err := os.Open(testPacketFile)
	if err != nil {
		t.Fatal(err)
	}

	defer f.Close()

	reader := New(f)
	el, err := openpgp.ReadKeyRing(reader)
	if err != nil {
		t.Fatal(err)
	}

	helperDumpPrivKeys(el, reader, t)
}

func TestArmorReader(t *testing.T) {
	f, err := os.Open(testArmorPacketFile)
	if err != nil {
		t.Fatal(err)
	}

	defer f.Close()

	reader, err := NewArmored(f)
	if err != nil {
		t.Fatal(err)
	}
	el, err := openpgp.ReadKeyRing(reader)
	if err != nil {
		t.Fatal(err)
	}

	helperDumpPrivKeys(el, reader, t)
}
