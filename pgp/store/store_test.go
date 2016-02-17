package store

import "testing"

func TestStoreInit(t *testing.T) {
	s := &KeyRing{}
	err := s.Init()
	if err != nil {
		t.Fatal(err)
	}
}
