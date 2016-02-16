[![GoDoc](https://godoc.org/github.com/jsipprell/keyctl/pgp?status.svg)](https://godoc.org/github.com/jsipprell/keyctl/pgp)

# keyctl/pgp

A "helper" package for use with the `golang.org/x/crypto/openpgp` package which can transparently cache private key passphrases using the
linux kernel's secure keyring system. Such cached passphrases can automatically expire after a configurable duration.

## Usage

To use, simply import the parent pkg `keyctl`, open the user session keyring, embed it in a static `pgp.PassphraseKeyring` struct and call
`ReadMessage` on this struct instead of using `goglang.org/x/crypto/openpgp.ReadMessage`. To customize the passphrase prompt, either
assign your own `pgp.Prompter` compatible interface to `PassphraseKeyring` or pass in an `openpgp.PromptFunction` in the `ReadMessage()`
method call.

For convenience, an `openpgp.PromptFunction` compatible func named `PassphrasePrompt` is exposed in the package.

## Example

```go
package main

import (
  "io"
  "log"
  "golang.org/x/crypto/openpgp"
  "github.com/jsipprell/keyctl"
  "github.com/jsipprell/keyctl/pgp"
)

func decryptReader(r io.Reader, pgpKeyring openpgp.KeyRing) {
  kr, err := keyctl.UserSessionKeyring()
  if err != nil {
    log.Fatal(err)
  }
  
  pkr := pgp.PassphraseKeyring{Keyring:kr}
  // Discard passphrases after 10 minutes
  pkr.SetDefaultTimeout(600)

  msgDetails, err := pkr.ReadMessage(r, pgpKeyring, pgp.PassphrasePrompt, nil)
  if err != nil {
    log.Fatal(err)
  }
  log.Printf("%#v\n", msgDetails)
}
