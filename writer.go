package keyctl

import (
	"bytes"
	"io"
)

type writer struct {
	*bytes.Buffer
	key    *Key
	closed bool
}

// Close a stream writer. *This MUST be called in order to flush the key value
// to the kernel
func (w *writer) Close() error {
	if !w.closed {
		w.closed = true
		b := w.Bytes()
		err := updateKey(w.key.id, b)
		if err == nil && w.key.ttl != 0 {
			err = w.key.ExpireAfter(uint(w.key.ttl.Seconds()))
		}
		return err
	}
	return nil
}

// Create a new stream writer to write key data to. The writer MUST Close the
// write stream to flush the key to the kernel.
func NewWriter(key *Key) io.Writer {
	return &writer{Buffer: bytes.NewBuffer(make([]byte, 0, 1024)), key: key}
}
