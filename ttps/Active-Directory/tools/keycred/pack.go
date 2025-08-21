package keycred

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

type consumer struct {
	data  []byte
	index int
	bo    binary.ByteOrder
}

func newConsumer(data []byte, byteOrder binary.ByteOrder) *consumer {
	return &consumer{
		data:  data,
		index: 0,
		bo:    byteOrder,
	}
}

func (c *consumer) advance(size int) []byte {
	if size <= 0 {
		return nil
	}

	c.index += size
	if c.index > len(c.data) {
		return make([]byte, size)
	}

	data := c.data[c.index-size : c.index]

	return data
}

func (c *consumer) Index() int {
	return c.index
}

func (c *consumer) Size() int {
	return len(c.data)
}

func (c *consumer) Uint16() uint16 {
	return c.bo.Uint16(c.advance(2))
}

func (c *consumer) Uint32() uint32 {
	return c.bo.Uint32(c.advance(4))
}

func (c *consumer) Uint64() uint64 {
	return c.bo.Uint64(c.advance(8))
}

func (c *consumer) Bytes(size int) []byte {
	return c.advance(size)
}

func (c *consumer) Byte() byte {
	return c.advance(1)[0]
}

func (c *consumer) Uint8() uint8 {
	return c.Byte()
}

func (c *consumer) Remaining() int {
	return len(c.data) - c.index
}

func (c *consumer) Error() error {
	remaining := c.Remaining()

	if remaining < 0 {
		return fmt.Errorf("%d bytes missing (%d bytes of data available with read head already at index %d)",
			-remaining, c.Size(), c.Index())
	}

	if remaining > 0 {
		return fmt.Errorf("%d unread bytes (%d bytes of data available with read head at index %d)",
			remaining, c.Size(), c.Index())
	}

	return nil
}

func writeBinary(w io.Writer, order binary.ByteOrder, value ...any) (err error) {
	for _, v := range value {
		err = binary.Write(w, order, v)
		if err != nil {
			return err
		}
	}

	return nil
}

func packBytes(order binary.ByteOrder, value ...any) []byte {
	var buf bytes.Buffer

	err := writeBinary(&buf, order, value...)
	if err != nil {
		panic(err.Error())
	}

	return buf.Bytes()
}
