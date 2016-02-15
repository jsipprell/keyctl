// Copyright 2015 Jesse Sipprell. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Provides a keyring with an openpgp.ReadMessage wrapper
// method that when called will automatically attempt
// private key decryption and save the passphrase in the
// private session kernel keyring for a configurable
// amount of time. If an encrypted private key is seen again
// before it expires, the original PromptFunction will not
// be called (unless decryption fails)
package pgp

import (
	"io"

	"github.com/jsipprell/keyctl"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

// A standard passphrase prompting interface
type Prompter interface {
	Prompt([]openpgp.Key, bool) ([]byte, error)
}

// A wrapper keyring that can automatically decrypt openpgp secret keys if the
// passphrase was previously used by the keyring (and the ttl has not expired)
// Such caching lives beyond the lifetime of the current process unless the
// process or thread keyring is used.
type PassphraseKeyring struct {
	keyctl.Keyring
	Prompt Prompter
}

type passphrase struct {
	keyctl.Keyring
	handler Prompter
	tried   map[uint64]struct{}
}

type prompter openpgp.PromptFunction

// Create a new Prompter from an openpgp prompting function
func NewPrompter(prompt openpgp.PromptFunction) Prompter {
	return prompter(prompt)
}

func (fn prompter) Prompt(keys []openpgp.Key, symmetric bool) ([]byte, error) {
	return fn(keys, symmetric)
}

// A look-alike to "golang.org/x/crypto/opengpg".ReadMessage.  When called it
// calls the openpgp.ReadMessage function, passing the io.Reader and
// openpgp.Keyring verbatim but in
func (pkr PassphraseKeyring) ReadMessage(r io.Reader, keyring openpgp.KeyRing,
	prompt interface{}, config *packet.Config) (*openpgp.MessageDetails, error) {
	var handler Prompter
	switch t := prompt.(type) {
	case Prompter:
		handler = t
	case openpgp.PromptFunction:
		handler = NewPrompter(t)
	}

	if handler == nil {
		handler = pkr.Prompt
	}

	p := &passphrase{
		Keyring: pkr.Keyring,
		handler: handler,
		tried:   make(map[uint64]struct{}),
	}
	return openpgp.ReadMessage(r, keyring, p.check, config)
}

func (p *passphrase) check(keys []openpgp.Key, symmetric bool) ([]byte, error) {
	if symmetric {
		return p.handler.Prompt(keys, symmetric)
	}

	for _, k := range keys {
		if _, ok := p.tried[k.PrivateKey.KeyId]; !ok {
			p.tried[k.PrivateKey.KeyId] = struct{}{}
			if !k.PrivateKey.Encrypted {
				continue
			}
			if passkey, err := p.Search("pgp:" + k.PrivateKey.KeyIdString()); err == nil {
				if pass, err := passkey.Get(); err == nil {
					if err = k.PrivateKey.Decrypt(pass); err == nil {
						return nil, nil
					}
				}
			}
		}

		for _, k := range keys {
			if k.PrivateKey.Encrypted {
				pass, err := p.handler.Prompt([]openpgp.Key{k}, true)
				if err != nil {
					return nil, err
				}
				if err = k.PrivateKey.Decrypt(pass); err == nil {
					_, err = p.Add("pgp:"+k.PrivateKey.KeyIdString(), pass)
					return nil, err
				}
			}
		}
	}

	return p.handler.Prompt(nil, symmetric)
}
