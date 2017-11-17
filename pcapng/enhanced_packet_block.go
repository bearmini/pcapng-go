package pcapng

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/bearmini/pcapng-go/pcapng/blocktype"
	"github.com/bearmini/pcapng-go/pcapng/optioncode"
	"github.com/pkg/errors"
)

/*
4.3.  Enhanced Packet Block

   An Enhanced Packet Block (EPB) is the standard container for storing
   the packets coming from the network.  The Enhanced Packet Block is
   optional because packets can be stored either by means of this block
   or the Simple Packet Block, which can be used to speed up capture
   file generation; or a file may have no packets in it.  The format of
   an Enhanced Packet Block is shown in Figure 11.

   The Enhanced Packet Block is an improvement over the original, now
   obsolete, Packet Block (Appendix A):

   o  it stores the Interface Identifier as a 32-bit integer value.
      This is a requirement when a capture stores packets coming from a
      large number of interfaces

   o  unlike the Packet Block (Appendix A), the number of packets
      dropped by the capture system between this packet and the previous
      one is not stored in the header, but rather in an option of the
      block itself.

      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +---------------------------------------------------------------+
    0 |                    Block Type = 0x00000006                    |
      +---------------------------------------------------------------+
    4 |                      Block Total Length                       |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    8 |                         Interface ID                          |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   12 |                        Timestamp (High)                       |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   16 |                        Timestamp (Low)                        |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   20 |                    Captured Packet Length                     |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   24 |                    Original Packet Length                     |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   28 /                                                               /
      /                          Packet Data                          /
      /              variable length, padded to 32 bits               /
      /                                                               /
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      /                                                               /
      /                      Options (variable)                       /
      /                                                               /
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                      Block Total Length                       |
      +---------------------------------------------------------------+

                  Figure 11: Enhanced Packet Block Format

   The Enhanced Packet Block has the following fields:

   o  Block Type: The block type of the Enhanced Packet Block is 6.

   o  Block Total Length: total size of this block, as described in
      Section 3.1.

   o  Interface ID: it specifies the interface this packet comes from;
      the correct interface will be the one whose Interface Description
      Block (within the current Section of the file) is identified by
      the same number (see Section 4.2) of this field.  The interface ID
      MUST be valid, which means that an matching interface description
      block MUST exist.

   o  Timestamp (High) and Timestamp (Low): upper 32 bits and lower 32
      bits of a 64-bit timestamp.  The timestamp is a single 64-bit
      unsigned integer that represents the number of units of time that
      have elapsed since 1970-01-01 00:00:00 UTC.  The length of a unit
      of time is specified by the 'if_tsresol' option (see Figure 10) of
      the Interface Description block referenced by this packet.  Note
      that, unlike timestamps in the libpcap file format, timestamps in
      Enhanced Packet Blocks are not saved as two 32-bit values that
      represent the seconds and microseconds that have elapsed since
      1970-01-01 00:00:00 UTC.  Timestamps in Enhanced Packet Blocks are
      saved as two 32-bit words that represent the upper and lower 32
      bits of a single 64-bit quantity.

   o  Captured Packet Length: number of octets captured from the packet
      (i.e. the length of the Packet Data field).  It will be the
      minimum value among the Original Packet Length and the snapshot
      length for the interface (SnapLen, defined in Figure 10).  The
      value of this field does not include the padding octets added at
      the end of the Packet Data field to align the Packet Data field to
      a 32-bit boundary.

   o  Original Packet Length: actual length of the packet when it was
      transmitted on the network.  It can be different from Captured
      Packet Length if the packet has been truncated by the capture
      process.

   o  Packet Data: the data coming from the network, including link-
      layer headers.  The actual length of this field is Captured Packet
      Length plus the padding to a 32-bit boundary.  The format of the
      link-layer headers depends on the LinkType field specified in the
      Interface Description Block (see Section 4.2) and it is specified
      in the entry for that format in the the tcpdump.org link-layer
      header types registry [2].

   o  Options: optionally, a list of options (formatted according to the
      rules defined in Section 3.5) can be present.

   In addition to the options defined in Section 3.5, the following
   options are valid within this block:

          +---------------+------+----------+-------------------+
          | Name          | Code | Length   | Multiple allowed? |
          +---------------+------+----------+-------------------+
          | epb_flags     | 2    | 4        | no                |
          | epb_hash      | 3    | variable | yes               |
          | epb_dropcount | 4    | 8        | no                |
          +---------------+------+----------+-------------------+

                  Table 4: Enhanced Packet Block Options

   epb_flags:
           The epb_flags option is a 32-bit flags word containing link-
           layer information.  A complete specification of the allowed
           flags can be found in Section 4.3.1.

           Example: '0'.

   epb_hash:
           The epb_hash option contains a hash of the packet.  The first
           octet specifies the hashing algorithm, while the following
           octets contain the actual hash, whose size depends on the
           hashing algorithm, and hence from the value in the first
           octet.  The hashing algorithm can be: 2s complement
           (algorithm octet = 0, size=XXX), XOR (algorithm octet = 1,
           size=XXX), CRC32 (algorithm octet = 2, size = 4), MD-5
           (algorithm octet = 3, size=XXX), SHA-1 (algorithm octet = 4,
           size=XXX).  The hash covers only the packet, not the header
           added by the capture driver: this gives the possibility to
           calculate it inside the network card.  The hash allows easier
           comparison/merging of different capture files, and reliable
           data transfer between the data acquisition system and the
           capture library.

           Examples: '02 EC 1D 87 97', '03 45 6E C2 17 7C 10 1E 3C 2E 99
           6E C2 9A 3D 50 8E'.

   epb_dropcount:
           The epb_dropcount option is a 64-bit integer value specifying
           the number of packets lost (by the interface and the
           operating system) between this packet and the preceding one
           for the same interface or, for the first packet for an
           interface, between this packet and the start of the capture
           process.

           Example: '0'.

*/
type EnhancedPacketBlock struct {
	BlockType            blocktype.BlockType
	BlockTotalLength     uint32
	InterfaceID          uint32
	TimestampHigh        uint32
	TimestampLow         uint32
	CapturedPacketLength uint32
	OriginalPacketLength uint32
	PacketData           []byte
	Options              EnhancedPacketBlockOptions
}

func (b *EnhancedPacketBlock) GetType() blocktype.BlockType {
	return b.BlockType
}

func (b *EnhancedPacketBlock) String() string {
	return fmt.Sprintf("%s block_len:%d if_id:%08x ts_hi:%d ts_lo:%d cap_len:%d orig_len:%d options:{%s} data:%s",
		b.BlockType.String(), b.BlockTotalLength, b.InterfaceID, b.TimestampHigh, b.TimestampLow, b.CapturedPacketLength, b.OriginalPacketLength, b.Options.String(), hex.EncodeToString(b.PacketData))
}

type EnhancedPacketBlockOptions struct {
	Flags         *EnhancedPacketBlockFlags
	Hash          []byte
	DropCount     *uint64
	Comments      []string
	CustomOptions []CustomOption
}

func (o EnhancedPacketBlockOptions) String() string {
	options := make([]string, 0)
	if o.Flags != nil {
		options = append(options, fmt.Sprintf("flags:%04x", *o.Flags))
	}
	if o.Hash != nil {
		options = append(options, fmt.Sprintf("hash:%s", hex.EncodeToString(o.Hash)))
	}
	if o.DropCount != nil {
		options = append(options, fmt.Sprintf("drop_count:%d", *o.DropCount))
	}

	return strings.Join(options, ",")
}

func (r *Reader) parseEnhancedPacketBlock(blockTotalLength uint32, bodyBytes []byte) (*EnhancedPacketBlock, error) {
	br := newEndiannessAwareReader(r.endian, bytes.NewReader(bodyBytes))
	ifid, err := br.readUint32()
	if err != nil {
		return nil, errors.Wrap(err, "unable to read interface id")
	}
	tshi, err := br.readUint32()
	if err != nil {
		return nil, errors.Wrap(err, "unable to read timestamp high")
	}
	tslo, err := br.readUint32()
	if err != nil {
		return nil, errors.Wrap(err, "unable to read timestamp low")
	}
	capLen, err := br.readUint32()
	if err != nil {
		return nil, errors.Wrap(err, "unable to read captured packet length")
	}
	origLen, err := br.readUint32()
	if err != nil {
		return nil, errors.Wrap(err, "unable to read original packet length")
	}
	data, err := br.readBytes(uint(capLen))
	if err != nil {
		return nil, errors.Wrap(err, "unable to read packet data")
	}

	var opts EnhancedPacketBlockOptions
loop:
	for {
		oc, err := br.readUint16()
		if err != nil {
			break
		}
		ol, err := br.readUint16()
		if err != nil {
			break
		}

		switch optioncode.OptionCode(oc) {
		case optioncode.EndOfOpt:
			break loop

		case optioncode.Comment:
			readCommonOptionComment(ol, br, &opts.Comments)

		case optioncode.CustomUTF8, optioncode.CustomUTF8WithoutNull, optioncode.CustomBinary, optioncode.CustomBinaryShouldNotCopied:
			err := readCustomOption(oc, ol, br, &opts.CustomOptions)
			if err != nil {
				return nil, err
			}

		case optioncode.EPB_Flags:
			if ol != 4 {
				return nil, errors.New("invalid option length for epb_flags")
			}
			fv, err := br.readUint32()
			if err != nil {
				return nil, errors.Wrap(err, "unable to read epb_flags")
			}
			f := ParseEnhancedPacketBlockFlags(fv)
			opts.Flags = &f

		case optioncode.EPB_Hash:
			h, err := br.readBytes(uint(ol))
			if err != nil {
				return nil, errors.Wrap(err, "unable to read epb_hash")
			}
			opts.Hash = h

		case optioncode.EPB_DropCount:
			if ol != 8 {
				return nil, errors.New("invalid option length for epb_dropcount")
			}
			dc, err := br.readUint64()
			if err != nil {
				return nil, errors.Wrap(err, "unable to read epb_dropcount")
			}
			opts.DropCount = &dc

		default:
			_, err := br.readBytes(uint(ol))
			if err != nil {
				return nil, errors.Wrapf(err, "unable to read unknown option (%d)", oc)
			}
		}

		// read padding
		padLen := 4 - (ol & 0x3)
		_, err = br.readBytes(uint(padLen))
		if err != nil {
			return nil, errors.Wrap(err, "unable to read padding in an option value")
		}
	}

	return &EnhancedPacketBlock{
		BlockType:            blocktype.EnhancedPacket,
		BlockTotalLength:     blockTotalLength,
		InterfaceID:          ifid,
		TimestampHigh:        tshi,
		TimestampLow:         tslo,
		CapturedPacketLength: capLen,
		OriginalPacketLength: origLen,
		PacketData:           data,
		Options:              opts,
	}, nil
}
