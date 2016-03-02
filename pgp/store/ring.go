package store

import (
	"bytes"
	_ "fmt"
	"strconv"
	"strings"

	"github.com/jsipprell/keyctl"
	"golang.org/x/crypto/openpgp"
)

// Implements openpgp.KeyRing interface
func mkident(id uint64) []byte {
	val := strconv.AppendUint(make([]byte, 0, 16), id, 16)
	if l := len(val); l < 16 {
		val = append(val[:16-l], val...)

		for i := 0; i < 16-l; i++ {
			val[i] = '0'
		}
	}

	return bytes.ToUpper(val)
}

func mkpubident(id []byte) string {
	b := append(make([]byte, 0, 28), []byte(pubKeyPrefix)...)
	return string(append(append(b, ':'), id...))
}

func mkprivident(id []byte) string {
	b := append(make([]byte, 0, 28), []byte(privKeyPrefix)...)
	return string(append(append(b, ':'), id...))
}

func getKeyEntitiesById(kr *KeyRing, id uint64) (el openpgp.EntityList, ring keyctl.Keyring, err error) {
	ident := mkident(id)

	k, err := kr.LiveKeyring.Search(mkprivident(ident))
	if err == nil {
		el, err = openpgp.ReadKeyRing(keyctl.NewReader(k))
		if err != nil {
			el = nil
			err = nil
		}
		if len(el) > 0 {
			ring = kr.LiveKeyring
			for _, ent := range el {
				if ent.PrivateKey != nil {
					if ent.PrivateKey.Encrypted {
						ring = kr.PrivateKeyring
					}
					break
				}
			}
		}
	}

	if len(el) == 0 {
		ring = kr.PublicKeyring
		if k, err = ring.Search(mkpubident(ident)); err == nil {
			el, err = openpgp.ReadKeyRing(keyctl.NewReader(k))
		}
	}

	return
}

func (kr *KeyRing) KeysById(id uint64) (keys []openpgp.Key) {
	el, _, err := getKeyEntitiesById(kr, id)
	if err == nil && len(el) > 0 {
		keys = el.KeysById(id)
	}
	return
}

func (kr *KeyRing) KeysByIdUsage(id uint64, requiredUsage byte) (keys []openpgp.Key) {
	el, _, err := getKeyEntitiesById(kr, id)
	if err == nil && len(el) > 0 {
		keys = el.KeysByIdUsage(id, requiredUsage)
	}
	return
}

func (kr *KeyRing) DecryptionKeys() (keys []openpgp.Key) {
	var el openpgp.EntityList
	refs, err := keyctl.ListKeyring(kr.PrivateKeyring)
	if err != nil || len(refs) == 0 {
		return
	}

	prefix := privKeyPrefix + ":"
	for _, r := range refs {
		info, err := r.Info()
		if err != nil {
			continue
		}
		if strings.HasPrefix(info.Name, prefix) {
			var (
				k  *keyctl.Key
				ok bool
			)
			if kv, err := r.Get(); err == nil {
				k, ok = kv.(*keyctl.Key)
			}
			if !ok {
				continue
			}
			kel, err := openpgp.ReadKeyRing(keyctl.NewReader(k))
			if err == nil && len(kel) > 0 {
				el = append(el, kel...)
			}
		}
	}

	return el.DecryptionKeys()
}
