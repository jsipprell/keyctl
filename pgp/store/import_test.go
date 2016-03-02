package store

import (
	"os"
	"testing"
)

const (
	testImportArmoredFile        = "test-import.asc"
	testImportFile               = "test-import.gpg"
	testImportPrivateArmoredFile = "test-import-private.asc"
	testImportPrivateFile        = "test-import-private.gpg"
)

func helperTestStoreKeyRing(t *testing.T) *KeyRing {
	s := &KeyRing{}
	err := s.Init()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestStoreImportArmored(t *testing.T) {
	ring := helperTestStoreKeyRing(t)

	f, err := os.Open(testImportArmoredFile)
	if err != nil {
		t.Fatal(err)
	}

	defer f.Close()
	if err = ImportArmoredInto(ring, f); err != nil {
		t.Fatal(err)
	}
}

func TestStoreImportPrivateArmored(t *testing.T) {
	ring := helperTestStoreKeyRing(t)

	f, err := os.Open(testImportPrivateArmoredFile)
	if err != nil {
		t.Fatal(err)
	}

	defer f.Close()
	if err = ImportArmoredInto(ring, f); err != nil {
		t.Fatal(err)
	}
}

func TestStoreImportPrivateUnarmored(t *testing.T) {
	ring := helperTestStoreKeyRing(t)

	f, err := os.Open(testImportPrivateFile)
	if err != nil {
		t.Fatal(err)
	}

	defer f.Close()
	if err = ImportInto(ring, f); err != nil {
		panic(err)
	}
}
