package store

import (
	"io"

	"github.com/jsipprell/keyctl/pgp/store/capture"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

type importReader interface {
	io.Reader

	PrivateKey(uint64) ([]byte, bool)
}

type keyIdStringer interface {
	KeyIdString() string
}

type privateKeyWithId struct {
	*packet.PrivateKey

	stringId string
}

func (pk privateKeyWithId) KeyIdString() string {
	return pk.stringId
}

func (pk privateKeyWithId) isEncrypted() bool {
	return pk.Encrypted
}

func importInto(kr *KeyRing, r importReader, fn func(io.Reader) (openpgp.EntityList, error)) (err error) {
	var (
		el openpgp.EntityList
	)

	importMap := make(map[string]*Key)
	priKeys := make(map[uint64][]openpgp.Key)
	if el, err = fn(r); err != nil {
		return
	}

	for _, ent := range el {
		id := ent.PrimaryKey.KeyId
		if _, ok := priKeys[id]; !ok {
			keys := el.KeysById(id)
			if len(keys) > 0 {
				priKeys[id] = keys
			}
		}
	}

	for _, pks := range priKeys {
		for _, pk := range pks {
			id := pk.Entity.PrimaryKey.KeyIdString()
			key, ok := importMap[id]
			if !ok {
				key, _ = loadPubKey(kr, id)
			}
			updateKey(key, key.flags, pk)
			importMap[id] = key
		}
	}

	for _, key := range importMap {
		if err = writeKey(kr, r.PrivateKey, key); err != nil {
			return
		}
	}
	return
}

// Import a stream of unarmored pgp keys
func ImportInto(kr *KeyRing, r io.Reader) error {
	return importInto(kr, capture.New(r), openpgp.ReadKeyRing)
}

func ImportArmoredInto(kr *KeyRing, r io.Reader) error {
	ar, err := capture.NewArmored(r)
	if err != nil {
		return err
	}
	return importInto(kr, ar, openpgp.ReadArmoredKeyRing)
}

func Import(r io.Reader) (*KeyRing, error) {
	kr := new(KeyRing)
	err := kr.Init()
	if err == nil {
		err = importInto(kr, capture.New(r), openpgp.ReadKeyRing)
	}
	return kr, err
}

func ImportArmored(r io.Reader) (*KeyRing, error) {
	kr := new(KeyRing)
	err := kr.Init()
	if err == nil {
		var ar importReader
		if ar, err = capture.NewArmored(r); err == nil {
			err = importInto(kr, ar, openpgp.ReadArmoredKeyRing)
		}
	}
	return kr, err
}
