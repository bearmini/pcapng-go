package pcapng

import (
	"encoding/binary"
	"io"

	"github.com/pkg/errors"
)

type endiannessAwareReader struct {
	endian binary.ByteOrder
	r      io.Reader
}

func newEndiannessAwareReader(endian binary.ByteOrder, r io.Reader) *endiannessAwareReader {
	return &endiannessAwareReader{
		endian: endian,
		r:      r,
	}
}

func (er *endiannessAwareReader) Read(b []byte) (int, error) {
	return er.r.Read(b)
}

func (er *endiannessAwareReader) readByte() (byte, error) {
	b := make([]byte, 1)
	nRead, err := er.r.Read(b)
	if err != nil {
		return 0, err
	}
	if nRead != 1 {
		return 0, errors.New("insufficient data to read a byte")
	}

	return b[0], nil
}

func (er *endiannessAwareReader) readBytes(n uint) ([]byte, error) {
	b := make([]byte, n)
	nRead, err := er.r.Read(b)
	if err != nil {
		return nil, err
	}
	if n != uint(nRead) {
		return nil, errors.Errorf("insufficient data to read %d bytes", n)
	}

	return b, nil
}

func (er *endiannessAwareReader) readString(n uint) (string, error) {
	b, err := er.readBytes(n)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (er *endiannessAwareReader) readUint8() (uint8, error) {
	b, err := er.readByte()
	return uint8(b), err
}

func (er *endiannessAwareReader) readUint16() (uint16, error) {
	if er.endian == nil {
		return 0, errors.New("endiannes is not set")
	}

	b := make([]byte, 2)
	n, err := er.r.Read(b)
	if err != nil {
		return 0, err
	}
	if n != len(b) {
		return 0, errors.New("insufficient bytes to read uint16")
	}

	return er.endian.Uint16(b), nil
}

func (er *endiannessAwareReader) readUint32() (uint32, error) {
	if er.endian == nil {
		return 0, errors.New("endiannes is not set")
	}

	b := make([]byte, 4)
	n, err := er.r.Read(b)
	if err != nil {
		return 0, err
	}
	if n != len(b) {
		return 0, errors.New("insufficient bytes to read uint32")
	}

	return er.endian.Uint32(b), nil
}

func (er *endiannessAwareReader) readUint64() (uint64, error) {
	if er.endian == nil {
		return 0, errors.New("endiannes is not set")
	}

	b := make([]byte, 8)
	n, err := er.r.Read(b)
	if err != nil {
		return 0, err
	}
	if n != len(b) {
		return 0, errors.New("insufficient bytes to read uint64")
	}

	return er.endian.Uint64(b), nil
}

func (er *endiannessAwareReader) readInt8() (int8, error) {
	u, err := er.readUint8()
	return int8(u), err
}

func (er *endiannessAwareReader) readInt16() (int16, error) {
	u, err := er.readUint16()
	return int16(u), err
}

func (er *endiannessAwareReader) readInt32() (int32, error) {
	u, err := er.readUint32()
	return int32(u), err
}

func (er *endiannessAwareReader) readInt64() (int64, error) {
	u, err := er.readUint64()
	return int64(u), err
}
