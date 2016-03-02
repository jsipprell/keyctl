package capture

import (
	"bytes"
	"io"
	"sync"

	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/errors"
	"golang.org/x/crypto/openpgp/packet"
)

const (
	packetTypePrivateKey    packetType = 5
	packetTypePrivateSubkey packetType = 7
)

type packetType uint8

func readFull(r io.Reader, buf []byte) (n int, err error) {
	n, err = io.ReadFull(r, buf)
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return
}

func readLength(r io.Reader) (l int64, isPartial bool, err error) {
	var buf [4]byte
	_, err = readFull(r, buf[:1])
	if err != nil {
		return
	}

	switch {
	case buf[0] < 192:
		l = int64(buf[0])
	case buf[0] < 224:
		l = int64(buf[0]-192) << 8
		if _, err = readFull(r, buf[0:1]); err != nil {
			return
		}
		l += int64(buf[0]) + 192
	case buf[0] < 255:
		l = int64(1) << (buf[0] & 0x1f)
		isPartial = true
	default:
		if _, err = readFull(r, buf[0:4]); err != nil {
			return
		}
		l = int64(buf[0])<<24 | int64(buf[1])<<16 | int64(buf[2])<<8 | int64(buf[3])
	}
	return
}

type partialLengthReader struct {
	r         io.Reader
	remaining int64
	isPartial bool
}

func (r *partialLengthReader) Read(p []byte) (n int, err error) {
	for r.remaining > 0 {
		if !r.isPartial {
			return 0, io.EOF
		}
		r.remaining, r.isPartial, err = readLength(r.r)
		if err != nil {
			return 0, nil
		}
	}

	toRead := int64(len(p))
	if toRead > r.remaining {
		toRead = r.remaining
	}

	n, err = r.r.Read(p[:int(toRead)])
	r.remaining -= int64(n)
	if n < int(toRead) && err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return
}

type spanReader struct {
	r io.Reader
	n int64
}

func (l *spanReader) Read(p []byte) (n int, err error) {
	if l.n <= 0 {
		return 0, io.EOF
	}

	if int64(len(p)) > l.n {
		p = p[0:l.n]
	}

	n, err = l.r.Read(p)
	l.n -= int64(n)
	if l.n > 0 && err == io.EOF {
		err = io.ErrUnexpectedEOF
	}

	return
}

func readHeader(r io.Reader) (tag packetType, length int64, contents io.Reader, err error) {
	var buf [4]byte

	if _, err = io.ReadFull(r, buf[:1]); err != nil {
		return
	}

	if buf[0]&0x80 == 0 {
		err = errors.StructuralError("tag [cap] byte does not have MSB set")
		return
	}

	if buf[0]&0x40 == 0 {
		tag = packetType((buf[0] & 0x3f) >> 2)
		lengthType := buf[0] & 3
		if lengthType == 3 {
			length = -1
			contents = r
			return
		}
		lengthBytes := 1 << lengthType
		if _, err = readFull(r, buf[0:lengthBytes]); err != nil {
			return
		}
		for i := 0; i < lengthBytes; i++ {
			length <<= 8
			length |= int64(buf[i])
		}
		contents = &spanReader{r, length}
		return
	}

	tag = packetType(buf[0] & 0x3f)

	var isPartial bool
	if length, isPartial, err = readLength(r); err != nil {
		return
	}

	if isPartial {
		contents = &partialLengthReader{
			remaining: length,
			isPartial: true,
			r:         r,
		}
		length = -1
	} else {
		contents = &spanReader{r, length}
	}
	return
}

type captureReader struct {
	*bytes.Buffer
	r io.Reader
}

func (c *captureReader) Read(p []byte) (n int, err error) {
	if n, err = c.r.Read(p); err == nil && n > 0 {
		c.Buffer.Write(p[:n])
	}
	return
}

type packetReader struct {
	r         io.Reader
	c         *captureReader
	capturing bool
}

func uncapture(pr *packetReader) {
	pr.capturing = false
	pr.c.Buffer = bytes.NewBuffer(pr.c.Bytes())
}

func (pr *packetReader) Read(p []byte) (n int, err error) {
	var add int

	if pr.capturing {
		if pr.c == nil {
			pr.c = &captureReader{Buffer: &bytes.Buffer{}, r: pr.r}
		}
		n, err = pr.c.Read(p)
		return
	}

	if pr.c != nil {
		if pr.c.Len() == 0 {
			pr.c = nil
			n, err = pr.r.Read(p)
			return
		}
		n, err = pr.c.Buffer.Read(p)
		if pr.c.Len() == 0 {
			pr.c = nil
		}
		if err != nil || n >= len(p) {
			return
		}
		add = n
		p = p[n:]
	}
	n, err = pr.r.Read(p)
	n += add
	return
}

type Reader struct {
	r    io.Reader
	pr   *packetReader
	keys map[uint64][]byte
	m    sync.Mutex
}

func (r *Reader) Read(p []byte) (int, error) {
	if r.pr != nil {
		if r.pr.capturing {
			uncapture(r.pr)
		}

		if r.pr.c != nil && r.pr.c.Len() > 0 {
			return r.pr.Read(p)
		}
	}
	r.pr = &packetReader{r: r.r, capturing: true}
	tag, _, _, err := readHeader(r.pr)
	if err != nil {
		return -1, err
	}
	pkt, err := packet.Read(io.MultiReader(bytes.NewBuffer(r.pr.c.Bytes()), r.pr))
	if err == nil {
		if tag == packetTypePrivateKey || tag == packetTypePrivateSubkey {
			r.m.Lock()
			defer r.m.Unlock()
			data := make([]byte, r.pr.c.Len())
			copy(data, r.pr.c.Bytes())
			r.keys[pkt.(*packet.PrivateKey).PublicKey.KeyId] = data
		}
	}
	uncapture(r.pr)
	return r.pr.Read(p)
}

func (r *Reader) PrivateKey(id uint64) (k []byte, ok bool) {
	r.m.Lock()
	defer r.m.Unlock()
	k, ok = r.keys[id]
	return
}

func New(r io.Reader) *Reader {
	return &Reader{r: r, keys: make(map[uint64][]byte)}
}

func NewArmored(r io.Reader) (*Reader, error) {
	p, err := armor.Decode(r)
	if err != nil {
		return nil, err
	}

	return &Reader{r: p.Body, keys: make(map[uint64][]byte)}, nil
}
