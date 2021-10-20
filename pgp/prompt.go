// Copyright 2015 Jesse Sipprell. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pgp

import (
	"io"
	"os"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/ssh/terminal"
)

// PassphrasePrompt asks for password in secure way via terminal
func PassphrasePrompt(keys []openpgp.Key, symmetric bool) ([]byte, error) {
	if len(keys) == 0 && !symmetric {
		return nil, io.EOF
	}
	oldState, err := terminal.MakeRaw(0)
	if err != nil {
		return nil, err
	}
	defer os.Stdout.Write([]byte{'\n'})
	defer terminal.Restore(0, oldState)
	if len(keys) > 0 {
		os.Stdout.Write([]byte("Enter passphrase for key " + keys[0].PrivateKey.KeyIdShortString() + " : "))
	} else {
		os.Stdout.Write([]byte("Enter passphrase: "))
	}
	return terminal.ReadPassword(0)
}
