# keyctl

[![GoDoc](https://pkg.go.dev/github.com/jsipprell/keyctl?status.svg)](https://pkg.go.dev/github.com/jsipprell/keyctl)
[![Build Status](https://travis-ci.org/jsipprell/keyctl.svg?branch=master)](https://travis-ci.org/jsipprell/keyctl)
[![Go Report Card](https://goreportcard.com/badge/github.com/jsipprell/keyctl)](https://goreportcard.com/report/github.com/jsipprell/keyctl)

A native Go API for the security key management system (aka "keyrings") found in Linux 2.6+

The keyctl interface is nominally provided by three or so Linux-specific syscalls, however it is almost always wrapped
in a library named `libkeyutils.so`.

This package interacts directly with the syscall interface and does not require CGO for linkage to the helper library
provided on most systems.

## Example Usages

To access the default session keyring (and create it if it doesn't exist)


```go    
package main
   
import (
  "log"
  "github.com/jsipprell/keyctl"
)
    
func main() {
  keyring, err := keyctl.SessionKeyring()
  if err != nil {
    log.Fatal(err)
  }
      
  // default timeout of 10 seconds for new or updated keys
  keyring.SetDefaultTimeout(10)
  secureData := []byte{1,2,3,4}
  id, err := keyring.Add("some-data", secureData)
  if err != nil {
    log.Fatal(err)
  }
  log.Printf("created session key id %v", id)
}
```

To search for an existing key by name:

```go
package main

import (
	"log"

	"github.com/jsipprell/keyctl"
)

func main() {
	keyring, err := keyctl.SessionKeyring()
	if err != nil {
		log.Fatal(err)
	}
	key, err := keyring.Search("some-data")
	if err != nil {
		log.Fatal(err)
	}

	data, err := key.Get()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("secure data: %v\n", data)
}
```

Running tests
===================

Ensure you have [GNU make](https://www.gnu.org/software/make/) installed.

```shell

    $ make check

```


Copyright: 2015 Jesse Sipprell. All rights reserved.
Use of this source code is governed by a BSD-style
license that can be found in the LICENSE file.

