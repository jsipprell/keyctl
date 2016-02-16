// Copyright 2015 Jesse Sipprell. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build linux

// A Go interface to linux kernel keyrings (keyctl interface)
package keyctl

// All Keys and Keyrings have unique 32-bit serial number identifiers.
type Id interface {
	Id() int32

	private()
}

type Keyring interface {
	Id
	Add(string, []byte) (Id, error)
	Search(string) (*Key, error)
	SetDefaultTimeout(uint)
}

type keyring struct {
	id         keyId
	defaultTtl uint
}

func (kr *keyring) private() {}

// Returns the 32-bit kernel identifier of a keyring
func (kr *keyring) Id() int32 {
	return int32(kr.id)
}

// Set a default timeout, in seconds, after which newly added keys will be
// destroyed.
func (kr *keyring) SetDefaultTimeout(nsecs uint) {
	kr.defaultTtl = nsecs
}

// Add a new key to a keyring. The key can be searched for later by name.
func (kr *keyring) Add(name string, key []byte) (Id, error) {
	r, err := add_key("user", name, key, int32(kr.id))
	if err == nil {
		key := &Key{Name: name, id: keyId(r), ring: kr.id}
		if kr.defaultTtl != 0 {
			err = key.ExpireAfter(kr.defaultTtl)
		}
		return key, err
	}

	return nil, err
}

// Search for a key by name, this also searches child keyrings linked to this
// one. The key, if found, is linked to the top keyring that Search() was called
// from.
func (kr *keyring) Search(name string) (*Key, error) {
	id, err := searchKeyring(kr.id, name)
	if err == nil {
		return &Key{Name: name, id: id, ring: kr.id}, nil
	}
	return nil, err
}

// Return the current login session keyring
func SessionKeyring() (Keyring, error) {
	return newKeyring(keySpecSessionKeyring)
}

// Return the current user-session keyring (part of session, but private to
// current user)
func UserSessionKeyring() (Keyring, error) {
	return newKeyring(keySpecUserSessionKeyring)
}

// Return the current group keyring.
func GroupKeyring() (Keyring, error) {
	return newKeyring(keySpecGroupKeyring)
}

// Return the keyring specific to the current executing thread.
func ThreadKeyring() (Keyring, error) {
	return newKeyring(keySpecThreadKeyring)
}

// Return the keyring specific to the current executing process.
func ProcessKeyring() (Keyring, error) {
	return newKeyring(keySpecProcessKeyring)
}
