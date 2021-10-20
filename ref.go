package keyctl

import (
	"bytes"
	"errors"
	"os"
	"strconv"
)

var (
	// ErrUnsupportedKeyType error is returned if the Get() method is called on a Reference that doesn't
	// represent a key or keychain.
	ErrUnsupportedKeyType = errors.New("unsupported keyctl key type")
	// ErrInvalidReference error is returned if a reference is stale when Info() or Get() is called on it.
	ErrInvalidReference = errors.New("invalid keyctl reference")
)

// Reference is a reference to an unloaded keyctl Key or Keychain. It can be
// dereferenced by calling the Get() method.
type Reference struct {
	// ID is the kernel key or keychain identifier referenced.
	ID     int32
	info   *Info
	parent keyID
}

// Info depicts information about a keyctl reference as returned by ref.Info()
type Info struct {
	Type, Name string
	UID, Gid   int
	Perm       KeyPerm

	valid bool
}

func getInfo(id keyID) (i Info, err error) {
	var desc []byte

	if desc, err = describeKeyID(id); err != nil {
		i.Name = err.Error()
		return
	}

	fields := bytes.Split(desc, []byte{';'})
	switch len(fields) {
	case 5:
		i.Name = string(fields[4])
		fallthrough
	case 4:
		p, _ := strconv.ParseUint(string(fields[3]), 16, 32)
		i.Perm = KeyPerm(p)
		fallthrough
	case 3:
		i.Gid, _ = strconv.Atoi(string(fields[2]))
		fallthrough
	case 2:
		i.UID, _ = strconv.Atoi(string(fields[1]))
		fallthrough
	case 1:
		if i.Type = string(fields[0]); i.Type == "user" {
			i.Type = "key"
		}
		i.valid = true
	default:
		panic("invalid field count from kernel keyctl describe sysctl")
	}
	return
}

// Permissions returns permissions in symbolic format.
func (i Info) Permissions() string {
	if i.UID == os.Geteuid() {
		return encodePerms(uint8(i.Perm >> KeyPerm(16)))
	}
	fsgid, err := getfsgid()
	if (err == nil && i.Gid == int(fsgid)) || i.Gid == os.Getegid() {
		return encodePerms(uint8(i.Perm >> KeyPerm(8)))
	}
	return encodePerms(uint8(i.Perm))
}

// Info returns Information about a keyctl reference.
func (r *Reference) Info() (i Info, err error) {
	if r.info == nil {
		i, err = getInfo(keyID(r.ID))
		r.info = &i
		return
	}

	return *r.info, err
}

// Valid returns true if the Info fetched by ref.Info() is valid.
func (i Info) Valid() bool {
	return i.valid
}

// Valid returns true if the keyctl reference is valid. References can become
// invalid if they have expired since the reference was created.
func (r *Reference) Valid() bool {
	if r.info == nil {
		i, err := r.Info()
		if err != nil {
			return false
		}
		return i.valid
	}
	return r.info.valid
}

// Get loads the referenced keyctl object, which must either be a key or a
// keyring otherwise ErrUnsupportedKeyType will be returned.
func (r *Reference) Get() (ID, error) {
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
	case "key", "big_key":
		return &Key{Name: r.info.Name, id: keyID(r.ID), ring: r.parent}, nil
	case "keyring":
		ring := &keyring{id: keyID(r.ID)}
		if r.ID > 0 && r.info.Name != "" {
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

// ListKeyring shows the contents of a keyring. Each contained object is represented by a
// Reference struct. Address information is available by calling ref.Info(), and
// contained objects which are keys or subordinate keyrings can be fetched by
// calling ref.Get()
func ListKeyring(kr Keyring) ([]Reference, error) {
	id := keyID(kr.ID())
	keys, err := listKeys(id)
	if err != nil {
		return nil, err
	}

	refs := make([]Reference, len(keys))

	for i, k := range keys {
		refs[i].ID, refs[i].parent = int32(k), id
	}

	return refs, nil
}
