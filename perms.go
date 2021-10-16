package keyctl

// Good read - https://man7.org/linux/man-pages/man7/keyrings.7.html

// KeyPerm represents in-kernel access control permission to keys and keyrings
// as a 32-bit integer broken up into four permission sets, one per byte.
// In MSB order, the perms are: Possessor, User, Group, Other.
type KeyPerm uint32

const (
	// PermOtherView shows other can view this key
	PermOtherView KeyPerm = 1 << iota
	// PermOtherRead shows other can read this key
	PermOtherRead
	// PermOtherWrite shows other can write this key
	PermOtherWrite
	// PermOtherSearch shows other can search this key
	PermOtherSearch
	// PermOtherLink shows other can link this key
	PermOtherLink
	// PermOtherSetattr shows other can set attributes to this key
	PermOtherSetattr
)

const (
	// PermGroupView shows group can view this key
	PermGroupView KeyPerm = 1 << (8 + iota)
	// PermGroupRead shows group can read this key
	PermGroupRead
	// PermGroupWrite shows group can write this key
	PermGroupWrite
	// PermGroupSearch shows group can search this key
	PermGroupSearch
	// PermGroupLink shows group can link this key
	PermGroupLink
	// PermGroupSetattr shows group can set attributes to this key
	PermGroupSetattr
)

const (
	// PermUserView shows user can viewthis key
	PermUserView KeyPerm = 1 << (16 + iota)
	// PermUserRead shows user can read this key
	PermUserRead
	// PermUserWrite shows user can write this key
	PermUserWrite
	// PermUserSearch shows user can search this key
	PermUserSearch
	// PermUserLink shows user can link this key
	PermUserLink
	// PermUserSetattr shows user can sett attributes to this key
	PermUserSetattr
)

const (
	// PermPossessorView shows processors can view this key
	PermPossessorView KeyPerm = 1 << (24 + iota)
	// PermPossessorRead shows processors can read this key
	PermPossessorRead
	// PermPossessorWrite shows processors can write this key
	PermPossessorWrite
	// PermPossessorSearch shows processors can search this key
	PermPossessorSearch
	// PermPossessorLink shows processors can link this key
	PermPossessorLink
	// PermPossessorSetattr shows process can set attributes to this key
	PermPossessorSetattr
)

const (
	// PermOtherAll shows others can do everything to this key
	PermOtherAll KeyPerm = 0x3f << (8 * iota)
	// PermGroupAll shows group can do everything to this key
	PermGroupAll
	// PermUserAll shows user can do everything to this key
	PermUserAll
	// PermPossessorAll shows process can do everything to this key
	PermPossessorAll
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

// Possess returns possess permissions in symbolic form
func (p KeyPerm) Possess() string {
	return encodePerms(uint8(uint(p) >> 24))
}

// Group returns the group permissions in symbolic form
func (p KeyPerm) Group() string {
	return encodePerms(uint8(uint(p) >> 8))
}

// User returns the user permissions in symbolic form
func (p KeyPerm) User() string {
	return encodePerms(uint8(uint(p) >> 16))
}

// Other returns other (default) permissions in symbolic form
func (p KeyPerm) Other() string {
	return encodePerms(uint8(p))
}

// String returns string representation of key permissions
func (p KeyPerm) String() string {
	return p.Possess()[2:] + p.User()[2:] + p.Group()[2:] + p.Other()[2:]
}

// Chown change user ownership on a key or keyring.
func Chown(k ID, user int) error {
	group := -1
	return keyctlChownFunc(keyID(k.ID()), user, group)
}

// Chgrp change group ownership on a key or keyring.
func Chgrp(k ID, group int) error {
	user := -1
	return keyctlChownFunc(keyID(k.ID()), user, group)
}

// SetPerm set permissions on a key or keyring.
func SetPerm(k ID, p KeyPerm) error {
	return keyctlSetPermFunc(keyID(k.ID()), uint32(p))
}
