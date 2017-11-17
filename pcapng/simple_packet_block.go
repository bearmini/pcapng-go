package pcapng

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/bearmini/pcapng-go/pcapng/blocktype"
	"github.com/pkg/errors"
)

/*
4.4.  Simple Packet Block

   The Simple Packet Block (SPB) is a lightweight container for storing
   the packets coming from the network.  Its presence is optional.

   A Simple Packet Block is similar to an Enhanced Packet Block (see
   Section 4.3), but it is smaller, simpler to process and contains only
   a minimal set of information.  This block is preferred to the
   standard Enhanced Packet Block when performance or space occupation
   are critical factors, such as in sustained traffic capture
   applications.  A capture file can contain both Enhanced Packet Blocks
   and Simple Packet Blocks: for example, a capture tool could switch
   from Enhanced Packet Blocks to Simple Packet Blocks when the hardware
   resources become critical.

   The Simple Packet Block does not contain the Interface ID field.
   Therefore, it MUST be assumed that all the Simple Packet Blocks have
   been captured on the interface previously specified in the first
   Interface Description Block.

   Figure 12 shows the format of the Simple Packet Block.

       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +---------------------------------------------------------------+
    0 |                    Block Type = 0x00000003                    |
      +---------------------------------------------------------------+
    4 |                      Block Total Length                       |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    8 |                    Original Packet Length                     |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   12 /                                                               /
      /                          Packet Data                          /
      /              variable length, padded to 32 bits               /
      /                                                               /
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                      Block Total Length                       |
      +---------------------------------------------------------------+

                   Figure 12: Simple Packet Block Format

   The Simple Packet Block has the following fields:

   o  Block Type: The block type of the Simple Packet Block is 3.

   o  Block Total Length: total size of this block, as described in
      Section 3.1.

   o  Original Packet Length: actual length of the packet when it was
      transmitted on the network.  It can be different from length of
      the Packet Data field's length if the packet has been truncated by
      the capture process, in which case the SnapLen value in
      Section 4.2 will be less than this Original Packet Length value,
      and the SnapLen value MUST be used to determine the size of the
      Packet Data field length.

   o  Packet Data: the data coming from the network, including link-
      layer headers.  The length of this field can be derived from the
      field Block Total Length, present in the Block Header, and it is
      the minimum value among the SnapLen (present in the Interface
      Description Block) and the Original Packet Length (present in this
      header).  The format of the data within this Packet Data field
      depends on the LinkType field specified in the Interface
      Description Block (see Section 4.2) and it is specified in the
      entry for that format in the tcpdump.org link-layer header types
      registry [3].

   The Simple Packet Block does not contain the timestamp because this
   is often one of the most costly operations on PCs.  Additionally,
   there are applications that do not require it; e.g. an Intrusion
   Detection System is interested in packets, not in their timestamp.

   A Simple Packet Block cannot be present in a Section that has more
   than one interface because of the impossibility to refer to the
   correct one (it does not contain any Interface ID field).

   The Simple Packet Block is very efficient in term of disk space: a
   snapshot whose length is 100 octets requires only 16 octets of
   overhead, which corresponds to an efficiency of more than 86%.

*/

type SimplePacketBlock struct {
	BlockType            blocktype.BlockType
	BlockTotalLength     uint32
	OriginalPacketLength uint32
	PacketData           []byte
}

func (b *SimplePacketBlock) String() string {
	return fmt.Sprintf("%s block_len:%d orig_len:%d data:%s",
		b.BlockType.String(), b.BlockTotalLength, b.OriginalPacketLength, hex.EncodeToString(b.PacketData))
}

func (b *SimplePacketBlock) GetType() blocktype.BlockType {
	return b.BlockType
}

func (r *Reader) parseSimplePacketBlock(blockTotalLength uint32, bodyBytes []byte) (*SimplePacketBlock, error) {
	br := newEndiannessAwareReader(r.endian, bytes.NewReader(bodyBytes))
	opl, err := br.readUint32()
	if err != nil {
		return nil, errors.Wrap(err, "unable to read original packet length")
	}
	data, err := br.readBytes(uint(opl))
	if err != nil {
		return nil, errors.Wrap(err, "unable to read packet data")
	}

	return &SimplePacketBlock{
		BlockType:            blocktype.SimplePacket,
		BlockTotalLength:     blockTotalLength,
		OriginalPacketLength: opl,
		PacketData:           data,
	}, nil
}
