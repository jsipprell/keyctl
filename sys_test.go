package keyctl

import "testing"

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
