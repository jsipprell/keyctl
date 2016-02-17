package keyctl

import "testing"

func mustInfo(r Reference) Info {
	info, err := r.Info()
	if err != nil {
		if msg := err.Error(); msg == "key has expired" {
			return Info{Name: msg}
		}
	}
	return info
}

func helperTestKeyRefs(ring Keyring, t *testing.T) []Reference {
	var err error

	if ring == nil {
		if ring, err = UserSessionKeyring(); err != nil {
			t.Fatal(err)
		}
	}

	refs, err := ListKeyring(ring)
	if err != nil {
		t.Fatal(err)
	}

	for _, r := range refs {
		t.Logf("%d: %+v [%s]\n", r.Id, mustInfo(r), mustInfo(r).Permissions())
	}

	return refs
}

func helperRecurseKeyringRefs(kr Keyring, t *testing.T) {
	for _, r := range helperTestKeyRefs(kr, t) {
		if !r.Valid() {
			continue
		}
		key, err := r.Get()
		if err != nil {
			t.Fatal(err)
		}
		switch k := key.(type) {
		case *namedKeyring:
			t.Logf("keyring %v: %q, parent %v", k.id, k.Name(), k.parent)
			helperRecurseKeyringRefs(k, t)
		case *keyring:
			t.Logf("keyring %v", k.id)
			helperRecurseKeyringRefs(k, t)
		case *Key:
			t.Logf("key %v: %q, keyring %v", k.id, k.Name, k.ring)
			data, err := k.Get()
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("   %v: %v", k.id, data)
		default:
			panic("unsupported type")
		}
	}
}

func TestUserSessionKeyringRefs(t *testing.T) {
	helperRecurseKeyringRefs(nil, t)
}
