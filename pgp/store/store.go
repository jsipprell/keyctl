package store

import (
	"crypto/rand"
	"io"
	"sync"
	"time"

	"github.com/jsipprell/keyctl"
)

const (
	defaultGroupPerm = keyctl.PermGroupAll ^ (keyctl.PermGroupWrite | keyctl.PermGroupSetattr)
	defaultOtherPerm = keyctl.PermOtherAll ^ (keyctl.PermOtherWrite | keyctl.PermOtherSetattr)

	privKeyPrefix         = "pgp-privkey"
	pubKeyPrefix          = "pgp-pubkey"
	defaultLiveKeyringTTL = 5 // nsecs decrypted keys live in live keyring
)

type KeyRing struct {
	// Source of cyrptographically secure entropy, defaults to
	// crypto/rand.Reader.
	Rand io.Reader

	// Root keyring to use if any of PublicKeyring, PrivateKeyring or
	// LiveKeyring is not set and thus must be created. Defaults to the session
	// keyring.
	RootKeyring keyctl.Keyring

	// PublicKeyring is where all public keys are stored. It is created
	// dynamically if not set and will have read-all permissions set.
	PublicKeyring keyctl.Keyring

	// PrivateKeyring is where all encrypted private keys are stored. It is
	// created dynamically if not set and will be only be accessible to the
	// current user.
	PrivateKeyring keyctl.Keyring

	// LiveKeyring is where all unencryped private keys which are imported are
	// stored (they are temporarily re-encrypted using a randomly generated
	// passphrase that can be discovered by calling LivePassphraseKey().
	LiveKeyring keyctl.Keyring

	LiveKeyringTTL time.Duration

	init sync.Once
}

func initialize(kr *KeyRing) (err error) {
	if kr.Rand == nil {
		kr.Rand = rand.Reader
	}
	if kr.LiveKeyringTTL == 0 {
		kr.LiveKeyringTTL = time.Duration(defaultLiveKeyringTTL) * time.Second
	} else if kr.LiveKeyringTTL < 0 {
		kr.LiveKeyringTTL = 0
	}

	if kr.RootKeyring == nil {
		if kr.RootKeyring, err = keyctl.SessionKeyring(); err != nil {
			return
		}
	}

	if kr.PublicKeyring == nil {
		if kr.PublicKeyring, err = openOrCreate(kr.RootKeyring, pubKeyPrefix); err != nil {
			return
		}
		if err = keyctl.SetPerm(kr.PublicKeyring, defaultGroupPerm|defaultOtherPerm|keyctl.PermUserAll); err != nil {
			return
		}
	}

	if kr.LiveKeyring == nil {
		if kr.LiveKeyring, err = openOrCreate(kr.RootKeyring, privKeyPrefix+"-live"); err != nil {
			return
		}
		if kr.LiveKeyringTTL/time.Second > 0 {
			kr.LiveKeyring.SetDefaultTimeout(uint(kr.LiveKeyringTTL / time.Second))
		}
		if err = keyctl.SetPerm(kr.LiveKeyring, keyctl.PermUserAll); err != nil {
			return
		}
	}
	if kr.PrivateKeyring == nil {
		if kr.PrivateKeyring, err = openOrCreate(kr.LiveKeyring, privKeyPrefix); err != nil {
			return
		}
		if err = keyctl.SetPerm(kr.PrivateKeyring, keyctl.PermUserAll); err != nil {
			return
		}
	}

	return
}

func openOrCreate(parent keyctl.Keyring, name string) (kr keyctl.Keyring, err error) {
	if kr, err = keyctl.OpenKeyring(parent, name); err == nil {
		return
	}

	kr, err = keyctl.CreateKeyring(parent, name)
	return
}

func (kr *KeyRing) Init() (err error) {
	kr.init.Do(func() {
		err = initialize(kr)
	})

	return
}
