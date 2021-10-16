package keyctl

// these constants apply only for ARM architecture
// Code is borrowed from
// https://github.com/nonoo/keyctl/commit/b6b7469de4a9f9515154d0799aceed891dc3104d

const (
	syscallKeyctlPTR   uintptr = 311
	syscallAddKeyPTR   uintptr = 309
	syscallSetFSGIDPTR uintptr = 139
)
