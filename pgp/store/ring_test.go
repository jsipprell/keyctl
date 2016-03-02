package store

import "testing"

func TestOpenPGPKeyring(t *testing.T) {
	s := helperTestStoreKeyRing(t)

	keys := s.KeysById(uint64(0xDDC1E8B734C81449))
	if len(keys) == 0 {
		t.Fatal("unable to load test keys")
	}
	for _, k := range keys {
		t.Logf("loaded key %q: %+v", k.PublicKey.KeyIdString(), k)
	}
}

func TestOpenPGPPrivateKey1(t *testing.T) {
	s := helperTestStoreKeyRing(t)

	keys := s.KeysById(uint64(0x01484C4E214C5F12))
	if len(keys) == 0 {
		t.Fatal("unable to load test keys")
	}
	for _, k := range keys {
		if k.PrivateKey != nil {
			t.Logf("found private key %q", k.PrivateKey.KeyIdString())
			goto testEachPGPPrivateKey1
		}
	}

	t.Fatal("unable to load private keys")
testEachPGPPrivateKey1:
}

func TestOpenPGPPrivateKey2(t *testing.T) {
	s := helperTestStoreKeyRing(t)

	keys := s.KeysById(uint64(0x134FFD6ABE7B858D))
	if len(keys) == 0 {
		t.Fatal("unable to load test keys")
	}
	for _, k := range keys {
		if k.PrivateKey != nil {
			t.Fatalf("found unexpected private key %q", k.PrivateKey.KeyIdString())
		}
		t.Logf("loaded key %q: %+v", k.PublicKey.KeyIdString(), k)
	}
}
