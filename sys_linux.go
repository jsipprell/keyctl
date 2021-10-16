package keyctl

import (
	"syscall"
	"unsafe"
)

type keyctlCommand int

type keyID int32

const (
	keySpecThreadKeyring      keyID = -1
	keySpecProcessKeyring     keyID = -2
	keySpecSessionKeyring     keyID = -3
	keySpecUserKeyring        keyID = -4
	keySpecUserSessionKeyring keyID = -5
	keySpecGroupKeyring       keyID = -6
	keySpecReqKeyAuthKey      keyID = -7
)

const (
	keyctlGetKeyringID keyctlCommand = iota
	keyctlJoinSessionKeyring
	keyctlUpdate
	keyctlRevoke
	keyctlChown
	keyctlSetPerm
	keyctlDescribe
	keyctlClear
	keyctlLink
	keyctlUnlink
	keyctlSearch
	keyctlRead
	keyctlInstantiate
	keyctlNegate
	keyctlSetReqKeyKeyring
	keyctlSetTimeout
	keyctlAssumeAuthority
)

var debugSyscalls bool

func (id keyID) ID() int32 {
	return int32(id)
}

func (cmd keyctlCommand) String() string {
	switch cmd {
	case keyctlGetKeyringID:
		return "keyctlGetKeyringID"
	case keyctlJoinSessionKeyring:
		return "keyctlJoinSessionKeyring"
	case keyctlUpdate:
		return "keyctlUpdate"
	case keyctlRevoke:
		return "keyctlRevoke"
	case keyctlChown:
		return "keyctlChown"
	case keyctlSetPerm:
		return "keyctlSetPerm"
	case keyctlDescribe:
		return "keyctlDescribe"
	case keyctlClear:
		return "keyctlClear"
	case keyctlLink:
		return "keyctlLink"
	case keyctlUnlink:
		return "keyctlUnlink"
	case keyctlSearch:
		return "keyctlSearch"
	case keyctlRead:
		return "keyctlRead"
	case keyctlInstantiate:
		return "keyctlInstantiate"
	case keyctlNegate:
		return "keyctlNegate"
	case keyctlSetReqKeyKeyring:
		return "keyctlSetReqKeyKeyring"
	case keyctlSetTimeout:
		return "keyctlSetTimeout"
	case keyctlAssumeAuthority:
		return "keyctlAssumeAuthority"
	}
	panic("bad arg")
}

func keyctlSetTimeoutFunc(id keyID, nsecs uint) error {
	_, _, errno := syscall.Syscall(syscallKeyctlPTR, uintptr(keyctlSetTimeout), uintptr(id), uintptr(nsecs))
	if errno != 0 {
		return errno
	}
	return nil
}

func keyctlReadFunc(id keyID, b *byte, size int) (int32, error) {
	v1, _, errno := syscall.Syscall6(syscallKeyctlPTR, uintptr(keyctlRead), uintptr(id), uintptr(unsafe.Pointer(b)), uintptr(size), 0, 0)
	if errno != 0 {
		return -1, errno
	}

	return int32(v1), nil
}

func keyctlLinkFunc(id, ring keyID) error {
	_, _, errno := syscall.Syscall(syscallKeyctlPTR, uintptr(keyctlLink), uintptr(id), uintptr(ring))
	if errno != 0 {
		return errno
	}
	return nil
}

func keyctlUnlinkFunc(id, ring keyID) error {
	_, _, errno := syscall.Syscall(syscallKeyctlPTR, uintptr(keyctlUnlink), uintptr(id), uintptr(ring))
	if errno != 0 {
		return errno
	}
	return nil
}

func keyctlChownFunc(id keyID, user, group int) error {
	_, _, errno := syscall.Syscall6(syscallKeyctlPTR, uintptr(keyctlChown), uintptr(id), uintptr(user), uintptr(group), 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func keyctlSetPermFunc(id keyID, perm uint32) error {
	_, _, errno := syscall.Syscall(syscallKeyctlPTR, uintptr(keyctlSetPerm), uintptr(id), uintptr(perm))
	if errno != 0 {
		return errno
	}
	return nil
}

func addKeyFunc(keyType, keyDesc string, payload []byte, id int32) (int32, error) {
	var (
		err    error
		errno  syscall.Errno
		b1, b2 *byte
		r1     uintptr
		pptr   unsafe.Pointer
	)

	if b1, err = syscall.BytePtrFromString(keyType); err != nil {
		return 0, err
	}

	if b2, err = syscall.BytePtrFromString(keyDesc); err != nil {
		return 0, err
	}

	if len(payload) > 0 {
		pptr = unsafe.Pointer(&payload[0])
	}
	r1, _, errno = syscall.Syscall6(syscallAddKeyPTR,
		uintptr(unsafe.Pointer(b1)),
		uintptr(unsafe.Pointer(b2)),
		uintptr(pptr),
		uintptr(len(payload)),
		uintptr(id),
		0)

	if errno != 0 {
		err = errno
		return 0, err
	}
	return int32(r1), nil
}

func getfsgid() (int32, error) {
	var (
		a1    int32
		err   error
		errno syscall.Errno
		r1    uintptr
	)

	a1 = -1
	if r1, _, errno = syscall.Syscall(syscallSetFSGIDPTR, uintptr(a1), 0, 0); errno != 0 {
		err = errno
		return int32(-1), err
	}
	return int32(r1), nil
}

func newKeyring(id keyID) (*keyring, error) {
	r1, _, errno := syscall.Syscall(syscallKeyctlPTR, uintptr(keyctlGetKeyringID), uintptr(id), uintptr(1))
	if errno != 0 {
		return nil, errno
	}

	if id >= 0 {
		id = keyID(r1)
	}
	return &keyring{id: id}, nil
}

func createKeyring(parent keyID, name string) (*keyring, error) {
	id, err := addKeyFunc("keyring", name, nil, int32(parent))
	if err != nil {
		return nil, err
	}

	return &keyring{id: keyID(id)}, nil
}

func searchKeyring(id keyID, name, keyType string) (keyID, error) {
	var (
		b1, b2 *byte
		err    error
	)

	if b1, err = syscall.BytePtrFromString(keyType); err != nil {
		return 0, err
	}
	if b2, err = syscall.BytePtrFromString(name); err != nil {
		return 0, err
	}
	r1, _, errno := syscall.Syscall6(syscallKeyctlPTR, uintptr(keyctlSearch), uintptr(id), uintptr(unsafe.Pointer(b1)), uintptr(unsafe.Pointer(b2)), 0, 0)
	if errno != 0 {
		err = errno
	}
	return keyID(r1), err
}

func describeKeyID(id keyID) ([]byte, error) {
	var (
		b1             []byte
		size, sizeRead int
	)

	b1 = make([]byte, 64)
	size = len(b1)
	sizeRead = size + 1
	for sizeRead > size {
		r1, _, errno := syscall.Syscall6(syscallKeyctlPTR, uintptr(keyctlDescribe), uintptr(id), uintptr(unsafe.Pointer(&b1[0])), uintptr(size), 0, 0)
		if errno != 0 {
			return nil, errno
		}
		if sizeRead = int(r1); sizeRead > size {
			b1 = make([]byte, sizeRead)
			size = sizeRead
			sizeRead++
		} else {
			size = sizeRead
		}
	}

	return b1[:size-1], nil
}

func listKeys(id keyID) ([]keyID, error) {
	var (
		b1             []byte
		size, sizeRead int
	)

	bsz := 4
	b1 = make([]byte, 16*bsz)
	size = len(b1)
	sizeRead = size + 1
	for sizeRead > size {
		r1, _, errno := syscall.Syscall6(syscallKeyctlPTR, uintptr(keyctlRead), uintptr(id), uintptr(unsafe.Pointer(&b1[0])), uintptr(size), 0, 0)
		if errno != 0 {
			return nil, errno
		}

		if sizeRead = int(r1); sizeRead > size {
			b1 = make([]byte, sizeRead)
			size = sizeRead
			sizeRead++
		} else {
			size = sizeRead
		}
	}
	keys := make([]keyID, size/bsz)
	for i := range keys {
		keys[i] = *((*keyID)(unsafe.Pointer(&b1[i*bsz])))
	}

	return keys, nil
}

func updateKey(id keyID, payload []byte) error {
	size := len(payload)
	if size == 0 {
		payload = make([]byte, 1)
	}
	_, _, errno := syscall.Syscall6(syscallKeyctlPTR, uintptr(keyctlUpdate), uintptr(id), uintptr(unsafe.Pointer(&payload[0])), uintptr(size), 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}
