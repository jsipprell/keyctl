package keyctl

import (
	"testing"
)

func TestAdd100BytesToUserSessionKeyring(t *testing.T) {
	ring, err := UserSessionKeyring()
	if err != nil {
		t.Fatal(err)
	}
	id, err := ring.Add("blank", make([]byte, 100))
	if err != nil {
		t.Fatal(err)
	}

	key := id.(*Key)
	t.Logf("added 100 byte empty key as: %v\n", key.Id())

	buf, err := key.Get()
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("read %d octets from key: %v\n", len(buf), buf)
}

func TestAdd128BytesToUserSessionExpireAfter10Seconds(t *testing.T) {
	ring, err := UserSessionKeyring()
	if err != nil {
		t.Fatal(err)
	}
	ring.SetDefaultTimeout(10)
	id, err := ring.Add("expire-test", make([]byte, 128))
	if err != nil {
		t.Fatal(err)
	}
	key := id.(*Key)
	t.Logf("added 128 byte empty key as: %v\n", key.Id())
}

func TestFetchKey(t *testing.T) {
	ring, err := UserSessionKeyring()
	if err != nil {
		t.Fatal(err)
	}
	key, err := ring.Search("blank")
	if err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 1024)
	r := NewReader(key)
	n, err := r.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("read %d octets from key: %v\n", n, buf[:n])
}

func TestFetchKeyFail(t *testing.T) {
	ring, err := UserSessionKeyring()
	if err != nil {
		t.Fatal(err)
	}
	_, err = ring.Search("abigbunchofnonsense")
	if err == nil {
		t.Fatal("search expected to fail")
	}
}

func TestUnlinkKey(t *testing.T) {
	ring, err := UserSessionKeyring()
	if err != nil {
		t.Fatal(err)
	}
	key, err := ring.Search("blank")
	if err != nil {
		t.Fatal(err)
	}
	if err = key.Unlink(); err != nil {
		t.Fatal(err)
	}
}
