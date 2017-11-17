package pcapng

import (
	"encoding/binary"
	"io"

	"github.com/bearmini/pcapng-go/pcapng/blocktype"
	"github.com/pkg/errors"
)

type Reader struct {
	er     *endiannessAwareReader
	endian binary.ByteOrder
}

func NewReader(r io.Reader) *Reader {
	return &Reader{
		er:     newEndiannessAwareReader(nil, r),
		endian: nil,
	}
}

func (r *Reader) ReadNextBlock() (Block, error) {
	bt, err := r.readBlockType()
	if err != nil {
		if err == io.EOF {
			return nil, nil
		}
		return nil, err
	}

	if *bt == blocktype.SectionHeader {
		return r.readSectionHeaderBlock()
	}

	btl, err := r.er.readUint32()
	if err != nil {
		return nil, errors.Wrap(err, "unable to read block total length")
	}
	if btl < 12 {
		return nil, errors.New("invalid block total length")
	}

	bodyBytes, err := r.er.readBytes(uint(btl - 12))
	if err != nil {
		return nil, errors.Wrap(err, "unable to read block total length")
	}

	btlTail, err := r.er.readUint32()
	if err != nil {
		return nil, errors.Wrap(err, "unable to read block total length at the bottom of the block")
	}
	if btl != btlTail {
		return nil, errors.Errorf("block total length fields are not matched: begin == %d, end == %d", btl, btlTail)
	}

	switch *bt {
	case blocktype.InterfaceDescription:
		return r.parseInterfaceDescriptionBlockBody(btl, bodyBytes)
	case blocktype.EnhancedPacket:
		return r.parseEnhancedPacketBlock(btl, bodyBytes)
	case blocktype.InterfaceStatistics:
		return r.parseInterfaceStatisticsBlock(btl, bodyBytes)
	case blocktype.NameResolution:
		return r.parseNameResolutionBlock(btl, bodyBytes)
	case blocktype.SimplePacket:
		return r.parseSimplePacketBlock(btl, bodyBytes)
	default:
		return r.parseGeneralBlock(*bt, btl, bodyBytes)
	}
}

func (r *Reader) readBlockType() (*blocktype.BlockType, error) {
	var btBytes [4]byte
	n, err := r.er.Read(btBytes[:])
	if err != nil {
		if err == io.EOF {
			return nil, err // no wrap
		}
		return nil, errors.Wrap(err, "unable to read block type")
	}
	if n != len(btBytes) {
		return nil, errors.New("insufficient data to read block type")
	}

	if r.endian != nil {
		bt := blocktype.BlockType(r.endian.Uint32(btBytes[:]))
		return &bt, nil
	}

	if btBytes[0] == 0x0a && btBytes[1] == 0x0d && btBytes[2] == 0x0d && btBytes[3] == 0x0a {
		bt := blocktype.SectionHeader
		return &bt, nil
	}

	return nil, errors.New("unable to detect block type")
}

func (r *Reader) readBlockTotalLength() (uint32, error) {
	if r.endian == nil {
		return 0, errors.New("unable to read block total length before endianness detected")
	}

	btl, err := r.er.readUint32()
	if err != nil {
		return 0, err
	}
	if btl < 12 {
		return 0, errors.New("invalid block total length")
	}

	return btl, nil
}
