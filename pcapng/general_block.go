package pcapng

import (
	"encoding/hex"
	"fmt"

	"github.com/bearmini/pcapng-go/pcapng/blocktype"
)

/*
From draft-tuexen-opsawg-pcapng November 13, 2017

http://xml2rfc.tools.ietf.org/cgi-bin/xml2rfc.cgi?url=https://raw.githubusercontent.com/pcapng/pcapng/master/draft-tuexen-opsawg-pcapng.xml&modeAsFormat=html/ascii&type=ascii#rfc.section.3


3.1.  General Block Structure

   A capture file is organized in blocks, that are appended one to
   another to form the file.  All the blocks share a common format,
   which is shown in Figure 1.

      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                          Block Type                           |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                      Block Total Length                       |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     /                          Block Body                           /
     /              variable length, padded to 32 bits               /
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                      Block Total Length                       |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                     Figure 1: Basic block structure.

   The fields have the following meaning:

   o  Block Type (32 bits): unique value that identifies the block.
      Values whose Most Significant Bit (MSB) is equal to 1 are reserved
      for local use.  They can be used to make extensions to the file
      format to save private data to the file.  The list of currently
      defined types can be found in Section 11.1.

   o  Block Total Length: total size of this block, in octets.  For
      instance, the length of a block that does not have a body is 12
      octets: 4 octets for the Block Type, 4 octets for the initial
      Block Total Length and 4 octets for the trailing Block Total
      Length.  This value MUST be a multiple of 4.

   o  Block Body: content of the block.

   o  Block Total Length: total size of this block, in octets.  This
      field is duplicated to permit backward file navigation.

   This structure, shared among all blocks, makes it easy to process a
   file and to skip unneeded or unknown blocks.  Some blocks can contain
   other blocks inside (nested blocks).  Some of the blocks are
   mandatory, i.e. a capture file is not valid if they are not present,
   other are optional.

   The General Block Structure allows defining other blocks if needed.
   A parser that does not understand them can simply ignore their
   content.
*/

type GeneralBlock struct {
	BlockType        blocktype.BlockType
	BlockTotalLength uint32
	BlockBody        []byte
}

func (b *GeneralBlock) GetType() blocktype.BlockType {
	return b.BlockType
}

func (b *GeneralBlock) String() string {
	return fmt.Sprintf("%s block_len:%d body:%s", b.BlockType.String(), b.BlockTotalLength, hex.EncodeToString(b.BlockBody))
}

func (r *Reader) parseGeneralBlock(blockType blocktype.BlockType, blockTotalLength uint32, bodyBytes []byte) (*GeneralBlock, error) {
	return &GeneralBlock{
		BlockType:        blockType,
		BlockTotalLength: blockTotalLength,
		BlockBody:        bodyBytes,
	}, nil
}
