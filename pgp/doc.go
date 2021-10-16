// Package pgp provides a keyring with an openpgp.ReadMessage wrapper
// method that when called will automatically attempt
// private key decryption and save the passphrase in the
// private session kernel keyring for a configurable
// amount of time. If an encrypted private key is seen again
// before it expires, the original PromptFunction will not
// be called (unless decryption fails)
package pgp

// Copyright 2015 Jesse Sipprell. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
