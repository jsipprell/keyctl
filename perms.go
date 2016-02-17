package keyctl

// KeyPerm represents in-kernel access control permission to keys and keyrings
// as a 32-bit integer broken up into four permission sets, one per byte.
// In MSB order, the perms are: Processor, User, Group, Other.
type KeyPerm uint32

const (
	PermOtherView KeyPerm = 1 << iota
	PermOtherRead
	PermOtherWrite
	PermOtherSearch
	PermOtherLink
	PermOtherSetattr
)

const (
	PermGroupView KeyPerm = 1 << (8 + iota)
	PermGroupRead
	PermGroupWrite
	PermGroupSearch
	PermGroupLink
	PermGroupSetattr
)

const (
	PermUserView KeyPerm = 1 << (16 + iota)
	PermUserRead
	PermUserWrite
	PermUserSearch
	PermUserLink
	PermUserSetattr
)

const (
	PermProcessView KeyPerm = 1 << (24 + iota)
	PermProcessRead
	PermProcessWrite
	PermProcessSearch
	PermProcessLink
	PermProcessSetattr
)

const (
	PermOtherAll KeyPerm = 0x3f << (8 * iota)
	PermGroupAll
	PermUserAll
	PermProcessAll
)

var permsChars = []byte("--alswrv")

func encodePerms(p uint8) string {
	l := uint(len(permsChars))
	out := make([]byte, l)

	l--
	for i, c := range permsChars {
		if p&(1<<(l-uint(i))) == 0 {
			out[i] = '-'
		} else {
			out[i] = c
		}
	}

	return string(out)
}

// Returns processor permissions in symbolic form
func (p KeyPerm) Process() string {
	return encodePerms(uint8(uint(p) >> 24))
}

// Returns the group permissions in symbolic form
func (p KeyPerm) Group() string {
	return encodePerms(uint8(uint(p) >> 8))
}

// Returns the user permissions in symbolic form
func (p KeyPerm) User() string {
	return encodePerms(uint8(uint(p) >> 16))
}

// Returns other (default) permissions in symbolic form
func (p KeyPerm) Other() string {
	return encodePerms(uint8(p))
}

func (p KeyPerm) String() string {
	return p.Process()[2:] + p.User()[2:] + p.Group()[2:] + p.Other()[2:]
}

// Change user ownership on a key or keyring.
func Chown(k Id, user int) error {
	group := -1

	_, _, err := keyctl(keyctlChown, uintptr(k.Id()), uintptr(user), uintptr(group))
	return err
}

// Change group ownership on a key or keyring.
func Chgrp(k Id, group int) error {
	user := -1

	_, _, err := keyctl(keyctlChown, uintptr(k.Id()), uintptr(user), uintptr(group))
	return err
}

// Set permissions on a key or keyring.
func SetPerm(k Id, p KeyPerm) error {
	_, _, err := keyctl(keyctlSetPerm, uintptr(k.Id()), uintptr(p))
	return err
}
