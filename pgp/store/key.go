package store

import (
	"io"
	"strings"

	_ "github.com/davecgh/go-spew/spew"
	"github.com/jsipprell/keyctl"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

const (
	storePublic storePending = 1 << iota
	storePrivate
	storeSubkeys
)

type storePending int

type Key struct {
	*openpgp.Key

	flags                             storePending
	pubkeyctl, privkeyctl, livekeyctl *keyctl.Key
}

func loadPubKey(kr *KeyRing, ident string) (*Key, error) {
	var (
		el  openpgp.EntityList
		key *Key
	)
	key = &Key{Key: new(openpgp.Key)}

	k, err := kr.PublicKeyring.Search(strings.Join([]string{pubKeyPrefix, ident}, ":"))
	if err != nil {
		return key, err
	}
	key.pubkeyctl = k
	r := keyctl.NewReader(k)
	el, err = openpgp.ReadKeyRing(r)
	if err == nil {
		if len(el) == 0 {
			return key, io.EOF
		}
		for _, ent := range el {
			if ent.PrimaryKey != nil && ent.PrimaryKey.KeyIdString() == ident {
				key.PublicKey = ent.PrimaryKey
				var selfSig *packet.Signature
				for _, sigid := range ent.Identities {
					if selfSig == nil {
						selfSig = sigid.SelfSignature
					} else if sigid.SelfSignature.IsPrimaryId != nil && *sigid.SelfSignature.IsPrimaryId {
						selfSig = sigid.SelfSignature
						break
					}
				}
				if selfSig != nil || key.Entity == nil {
					key.Entity = ent
				}
				key.SelfSignature = selfSig
			}
			if ent.PrivateKey != nil && key.PrivateKey == nil {
				if key.Entity == nil {
					key.Entity = ent
				}
				key.PrivateKey = ent.PrivateKey
			}
		}
	}

	return key, err
}

func updateKey(k *Key, flags storePending, ek openpgp.Key) {
	var isPrimary bool

	if k.PublicKey == nil || k.PublicKey != ek.Entity.PrimaryKey {
		k.PublicKey = ek.Entity.PrimaryKey
		flags |= storePublic
	}

	isPrimary = ek.SelfSignature != nil && ek.SelfSignature.IsPrimaryId != nil && *ek.SelfSignature.IsPrimaryId
	if k.Entity == nil || (k.Entity != ek.Entity && isPrimary) {
		k.Entity = ek.Entity
		flags |= storePublic
		if len(k.Entity.Subkeys) > 0 || len(k.Entity.Revocations) > 0 || len(k.Entity.Identities) > 0 {
			flags |= storeSubkeys
		}
	}

	if (k.PrivateKey == nil && ek.PrivateKey != nil) || isPrimary {
		k.PrivateKey = ek.PrivateKey
		flags |= storePrivate
	}
	k.flags = flags
}

func updateEntity(k *Key, flags storePending, ent *openpgp.Entity) {
	if ent != nil && ent.PrimaryKey != nil {
		if k.PublicKey != ent.PrimaryKey {
			k.PublicKey = ent.PrimaryKey
			flags |= storePublic
		}
	}

	if k.Entity == nil && ent != nil {
		if len(ent.Subkeys) > 0 || len(ent.Revocations) > 0 || len(ent.Identities) > 0 {
			flags |= storeSubkeys
		}
		k.Entity = ent
	}

	if ent.PrivateKey != nil {
		k.PrivateKey = ent.PrivateKey
		flags |= storePrivate
	}

	k.flags = flags
}

func getKeyWriter(kr *KeyRing, k *Key, v keyIdStringer) (keyctl.Flusher, error) {
	var (
		ring keyctl.Keyring
		name []string
		key  *keyctl.Key
	)

	switch t := v.(type) {
	case privateKeyWithId:
		name = []string{privKeyPrefix, t.KeyIdString()}
		if !t.isEncrypted() {
			key = k.privkeyctl
			ring = kr.PrivateKeyring
		} else {
			key = k.livekeyctl
			ring = kr.LiveKeyring
		}
	case keyIdStringer:
		name = []string{pubKeyPrefix, v.KeyIdString()}
		key = k.pubkeyctl
		ring = kr.PublicKeyring
	default:
		panic("unsupported key type")
	}

	if key == nil {
		return keyctl.CreateWriter(strings.Join(name, ":"), ring)
	}
	return keyctl.NewWriter(key), nil
}

func writeKey(kr *KeyRing, getPriv func(uint64) ([]byte, bool), k *Key) error {
	var (
		w   keyctl.Flusher
		err error
	)
	if k.flags&storePublic|storeSubkeys != 0 {
		switch {
		case k.PublicKey == nil && k.pubkeyctl != nil:
			if err = k.pubkeyctl.Unlink(); err == nil {
				k.pubkeyctl = nil
				k.flags &= ^(storePublic | storeSubkeys)
			}
		case k.PublicKey != nil:
			if w == nil {
				w, err = getKeyWriter(kr, k, k.PublicKey)
			}
			if err == nil {
				if err = k.Entity.Serialize(w); err == nil {
					w.Flush()
					k.flags &= ^(storePublic | storeSubkeys)
				}
			}
		}
	}

	if err == nil && k.flags&storePrivate != 0 {
		if w != nil {
			w.Close()
			w = nil
		}
		switch {
		case k.PrivateKey == nil:
			if k.livekeyctl != nil {
				keyctl.Unlink(kr.LiveKeyring, k.livekeyctl)
				keyctl.Unlink(kr.PrivateKeyring, k.livekeyctl)
				k.livekeyctl = nil
			}
			if k.privkeyctl != nil {
				keyctl.Unlink(kr.LiveKeyring, k.privkeyctl)
				keyctl.Unlink(kr.PrivateKeyring, k.privkeyctl)
				k.privkeyctl = nil
			}
			if err == nil {
				k.flags &= ^storePrivate
			}
		case k.PrivateKey != nil && k.PublicKey != nil:
			data, ok := getPriv(k.PrivateKey.KeyId)
			if !ok {
				break
			}
			w, err = getKeyWriter(kr, k, privateKeyWithId{PrivateKey: k.PrivateKey, stringId: k.PublicKey.KeyIdString()})
			if err == nil {
				// spew.Dump(data)
				if _, err = w.Write(data); err == nil {
					w.Close()
				} else {
					panic(err)
				}
				w = nil
			}
			if err == nil {
				k.flags &= ^storePrivate
			}
		}
	}

	if err == nil && w != nil {
		w.Close()
	}
	return err
}
