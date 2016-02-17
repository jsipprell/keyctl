package keyctl

import (
	"bytes"
	"errors"
	"strconv"
)

var (
	// Error returned if the Get() method is called on a Reference that doesn't
	// represent a key or keychain.
	ErrUnsupportedKeyType = errors.New("unsupported keyctl key type")
	// Error returned if a reference is stale when Info() or Get() is called on
	// it.
	ErrInvalidReference = errors.New("invalid keyctl reference")
)

// Reference is a reference to an unloaded keyctl Key or Keychain. It can be
// dereferenced by calling the Get() method.
type Reference struct {
	// Id is the kernel key or keychain identifier referenced.
	Id int32

	info   *Info
	parent keyId
}

// Information about a keyctl reference as returned by ref.Info()
type Info struct {
	Type, Name, Perm string
	Uid, Gid         int

	valid bool
}

// Return Information about a keyctl reference.
func (r *Reference) Info() (i Info, err error) {
	if r.info == nil {
		var desc []byte

		if desc, err = describeKeyId(keyId(r.Id)); err != nil {
			i.Name = err.Error()
			r.info = &i
			return
		}

		fields := bytes.Split(desc, []byte{';'})
		switch len(fields) {
		case 5:
			i.Name = string(fields[4])
			fallthrough
		case 4:
			i.Perm = string(fields[3])
			fallthrough
		case 3:
			i.Gid, _ = strconv.Atoi(string(fields[2]))
			fallthrough
		case 2:
			i.Uid, _ = strconv.Atoi(string(fields[1]))
			fallthrough
		case 1:
			if i.Type = string(fields[0]); i.Type == "user" {
				i.Type = "key"
			}
			i.valid = true
		default:
			panic("invalid field count from kernel keyctl describe sysctl")
		}
		r.info = &i
	} else {
		i = *r.info
	}

	return
}

// Returns true if the Info fetched by ref.Info() is valid.
func (i Info) Valid() bool {
	return i.valid
}

// Returns true if the keyctl reference is valid. Refererences can become
// invalid if they have expired since the reference was created.
func (r *Reference) Valid() bool {
	if r.info == nil {
		r.Info()
	}
	return r.info.valid
}

// Loads the referenced keyctl object, which must either be a key or a
// keyring otherwise ErrUnsupportedKeyType will be returned.
func (r *Reference) Get() (Id, error) {
	if r.info == nil {
		_, err := r.Info()
		if err != nil {
			return nil, err
		}
	}

	if !r.info.valid {
		return nil, ErrInvalidReference
	}

	switch r.info.Type {
	case "key":
		return &Key{Name: r.info.Name, id: keyId(r.Id), ring: r.parent}, nil
	case "keyring":
		ring := &keyring{id: keyId(r.Id)}
		if r.Id > 0 && r.info.Name != "" {
			return &namedKeyring{
				keyring: ring,
				parent:  r.parent,
				name:    r.info.Name,
			}, nil
		}
		return ring, nil
	default:
		return nil, ErrUnsupportedKeyType
	}
}

// List the contents of a keyring. Each contained object is represented by a
// Reference struct. Addl information is available by calling ref.Info(), and
// contained objects which are keys or subordinate keyrings can be fetched by
// calling ref.Get()
func ListKeyring(kr Keyring) ([]Reference, error) {
	id := keyId(kr.Id())
	keys, err := listKeys(id)
	if err != nil {
		return nil, err
	}

	refs := make([]Reference, len(keys))

	for i, k := range keys {
		refs[i].Id, refs[i].parent = int32(k), id
	}

	return refs, nil
}
