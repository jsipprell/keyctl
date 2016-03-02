package keyctl

import (
	"log"
	"syscall"
	"unsafe"
)

type keyctlCommand int

type keyId int32

const (
	keySpecThreadKeyring      keyId = -1
	keySpecProcessKeyring     keyId = -2
	keySpecSessionKeyring     keyId = -3
	keySpecUserKeyring        keyId = -4
	keySpecUserSessionKeyring keyId = -5
	keySpecGroupKeyring       keyId = -6
	keySpecReqKeyAuthKey      keyId = -7
)

const (
	keyctlGetKeyringId keyctlCommand = iota
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

func (id keyId) Id() int32 {
	return int32(id)
}

func (cmd keyctlCommand) String() string {
	switch cmd {
	case keyctlGetKeyringId:
		return "keyctlGetKeyringId"
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

func keyctl(cmd keyctlCommand, args ...uintptr) (r1 int32, r2 int32, err error) {
	a := make([]uintptr, 6)
	l := len(args)
	if l > 5 {
		l = 5
	}
	a[0] = uintptr(cmd)
	for idx, v := range args[:l] {
		a[idx+1] = v
	}
	if debugSyscalls {
		log.Printf("%v: %v %v\n", syscall_keyctl, cmd, a[1:])
	}
	v1, v2, errno := syscall.Syscall6(syscall_keyctl, a[0], a[1], a[2], a[3], a[4], a[5])
	if errno != 0 {
		err = errno
		return
	}

	r1 = int32(v1)
	r2 = int32(v2)
	return
}

func add_key(keyType, keyDesc string, payload []byte, id int32) (int32, error) {
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
	r1, _, errno = syscall.Syscall6(syscall_add_key,
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
	if r1, _, errno = syscall.Syscall(syscall_setfsgid, uintptr(a1), 0, 0); errno != 0 {
		err = errno
		return int32(-1), err
	}
	return int32(r1), nil
}

func newKeyring(id keyId) (*keyring, error) {
	r1, _, err := keyctl(keyctlGetKeyringId, uintptr(id), uintptr(1))
	if err != nil {
		return nil, err
	}

	if id < 0 {
		r1 = int32(id)
	}
	return &keyring{id: keyId(r1)}, nil
}

func createKeyring(parent keyId, name string) (*keyring, error) {
	id, err := add_key("keyring", name, nil, int32(parent))
	if err != nil {
		return nil, err
	}

	return &keyring{id: keyId(id)}, nil
}

func searchKeyring(id keyId, name, keyType string) (keyId, error) {
	var (
		r1     int32
		b1, b2 *byte
		err    error
	)

	if b1, err = syscall.BytePtrFromString(keyType); err != nil {
		return 0, err
	}
	if b2, err = syscall.BytePtrFromString(name); err != nil {
		return 0, err
	}

	r1, _, err = keyctl(keyctlSearch, uintptr(id), uintptr(unsafe.Pointer(b1)), uintptr(unsafe.Pointer(b2)))
	return keyId(r1), err
}

func describeKeyId(id keyId) ([]byte, error) {
	var (
		r1             int32
		b1             []byte
		err            error
		size, sizeRead int
	)

	b1 = make([]byte, 64)
	size = len(b1)
	sizeRead = size + 1
	for sizeRead > size {
		r1, _, err = keyctl(keyctlDescribe, uintptr(id), uintptr(unsafe.Pointer(&b1[0])), uintptr(size))
		if err != nil {
			return nil, err
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

func listKeys(id keyId) ([]keyId, error) {
	var (
		r1             int32
		b1             []byte
		err            error
		size, sizeRead int
	)

	bsz := int(unsafe.Sizeof(r1))
	b1 = make([]byte, 16*bsz)
	size = len(b1)
	sizeRead = size + 1
	for sizeRead > size {
		r1, _, err = keyctl(keyctlRead, uintptr(id), uintptr(unsafe.Pointer(&b1[0])), uintptr(size))

		if err != nil {
			return nil, err
		}

		if sizeRead = int(r1); sizeRead > size {
			b1 = make([]byte, sizeRead)
			size = sizeRead
			sizeRead++
		} else {
			size = sizeRead
		}
	}
	keys := make([]keyId, size/bsz)
	for i := range keys {
		keys[i] = *((*keyId)(unsafe.Pointer(&b1[i*bsz])))
	}

	return keys, nil
}

func updateKey(id keyId, payload []byte) error {
	size := len(payload)
	if size == 0 {
		payload = make([]byte, 1)
	}
	_, _, err := keyctl(keyctlUpdate, uintptr(id), uintptr(unsafe.Pointer(&payload[0])), uintptr(size))
	return err
}
