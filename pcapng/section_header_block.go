package pcapng

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/bearmini/pcapng-go/pcapng/optioncode"

	"github.com/bearmini/pcapng-go/pcapng/blocktype"
	"github.com/pkg/errors"
)

/*
4.1.  Section Header Block

   The Section Header Block (SHB) is mandatory.  It identifies the
   beginning of a section of the capture capture file.  The
   Section Header Block does not contain data but it rather identifies a
   list of blocks (interfaces, packets) that are logically correlated.
   Its format is shown in Figure 9.

      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +---------------------------------------------------------------+
    0 |                   Block Type = 0x0A0D0D0A                     |
      +---------------------------------------------------------------+
    4 |                      Block Total Length                       |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    8 |                      Byte-Order Magic                         |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   12 |          Major Version        |         Minor Version         |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   16 |                                                               |
      |                          Section Length                       |
      |                                                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   24 /                                                               /
      /                      Options (variable)                       /
      /                                                               /
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                      Block Total Length                       |
      +---------------------------------------------------------------+

                   Figure 9: Section Header Block Format

   The meaning of the fields is:

   o  Block Type: The block type of the Section Header Block is the
      integer corresponding to the 4-char string "\r\n\n\r"
      (0x0A0D0D0A).  This particular value is used for 2 reasons:

      1.  This number is used to detect if a file has been transferred
          via FTP or HTTP from a machine to another with an
          inappropriate ASCII conversion.  In this case, the value of
          this field will differ from the standard one ("\r\n\n\r") and
          the reader can detect a possibly corrupted file.

      2.  This value is palindromic, so that the reader is able to
          recognize the Section Header Block regardless of the
          endianness of the section.  The endianness is recognized by
          reading the Byte Order Magic, that is located 8 octets after
          the Block Type.

   o  Block Total Length: total size of this block, as described in
      Section 3.1.

   o  Byte-Order Magic: magic number, whose value is the hexadecimal
      number 0x1A2B3C4D.  This number can be used to distinguish
      sections that have been saved on little-endian machines from the
      ones saved on big-endian machines.

   o  Major Version: number of the current mayor version of the format.
      Current value is 1.  This value should change if the format
      changes in such a way that code that reads the new format could
      not read the old format (i.e., code to read both formats would
      have to check the version number and use different code paths for
      the two formats) and code that reads the old format could not read
      the new format.

   o  Minor Version: number of the current minor version of the format.
      Current value is 0.  This value should change if the format
      changes in such a way that code that reads the new format could
      read the old format without checking the version number but code
      that reads the old format could not read all files in the new
      format.

   o  Section Length: a signed 64-bit value specifying the length in
      octets of the following section, excluding the Section Header
      Block itself.  This field can be used to skip the section, for
      faster navigation inside large files.  Section Length equal -1
      (0xFFFFFFFFFFFFFFFF) means that the size of the section is not
      specified, and the only way to skip the section is to parse the
      blocks that it contains.  Please note that if this field is valid
      (i.e. not negative), its value is always aligned to 32 bits, as
      all the blocks are aligned to and padded to 32-bit boundaries.
      Also, special care should be taken in accessing this field: since
      the alignment of all the blocks in the file is 32-bits, this field
      is not guaranteed to be aligned to a 64-bit boundary.  This could
      be a problem on 64-bit processors.

   o  Options: optionally, a list of options (formatted according to the
      rules defined in Section 3.5) can be present.

   Adding new block types or options would not necessarily require that
   either Major or Minor numbers be changed, as code that does not know
   about the block type or option should just skip it; only if skipping
   a block or option does not work should the minor version number be
   changed.

   Aside from the options defined in Section 3.5, the following options
   are valid within this block:

          +--------------+------+----------+-------------------+
          | Name         | Code | Length   | Multiple allowed? |
          +--------------+------+----------+-------------------+
          | shb_hardware | 2    | variable | no                |
          | shb_os       | 3    | variable | no                |
          | shb_userappl | 4    | variable | no                |
          +--------------+------+----------+-------------------+

                   Table 2: Section Header Block Options

   shb_hardware:
           The shb_hardware option is a UTF-8 string containing the
           description of the hardware used to create this section.

           Examples: "x86 Personal Computer", "Sun Sparc Workstation".

   shb_os:
           The shb_os option is a UTF-8 string containing the name of
           the operating system used to create this section.

           Examples: "Windows XP SP2", "openSUSE 10.2".

   shb_userappl:
           The shb_userappl option is a UTF-8 string containing the name
           of the application used to create this section.

           Examples: "dumpcap V0.99.7".

   [Open issue: does a program which re-writes a capture file change the
   original hardware/os/application info?]

*/

const byteOrderMagic uint32 = 0x1a2b3c4d

type SectionHeaderBlock struct {
	BlockType        blocktype.BlockType
	BlockTotalLength uint32
	ByteOrderMagic   uint32
	byteOrder        binary.ByteOrder
	MajorVersion     uint16
	MinorVersion     uint16
	SectionLength    int64
	Options          SectionHeaderBlockOptions
}

func (b *SectionHeaderBlock) String() string {
	bo := "LE"
	if b.byteOrder == binary.BigEndian {
		bo = "BE"
	}
	return fmt.Sprintf("%s block_len:%d byteorder:%s major:%d minor:%d section_len:%d options:{%s}",
		b.BlockType.String(), b.BlockTotalLength, bo, b.MajorVersion, b.MinorVersion, b.SectionLength, b.Options.String())
}

type SectionHeaderBlockOptions struct {
	Hardware      *string
	OS            *string
	UserAppl      *string
	Comments      []string
	CustomOptions []CustomOption
}

func (o *SectionHeaderBlockOptions) String() string {
	options := make([]string, 0)
	if o.Hardware != nil {
		options = append(options, fmt.Sprintf("hardware:%s", *o.Hardware))
	}
	if o.OS != nil {
		options = append(options, fmt.Sprintf("os:%s", *o.OS))
	}
	if o.UserAppl != nil {
		options = append(options, fmt.Sprintf("userappl:%s", *o.UserAppl))
	}

	return strings.Join(options, ",")
}

func (b *SectionHeaderBlock) GetType() blocktype.BlockType {
	return b.BlockType
}

func (r *Reader) readSectionHeaderBlock() (*SectionHeaderBlock, error) {
	var btlBytes [4]byte
	n, err := r.er.Read(btlBytes[:])
	if err != nil {
		return nil, errors.Wrap(err, "unable to read block total length")
	}
	if n != len(btlBytes) {
		return nil, errors.New("insufficient data to read block total length")
	}
	// we cannot recognize Block Total Length here because we don't have any endianness info yet

	var bomBytes [4]byte
	n, err = r.er.Read(bomBytes[:])
	if err != nil {
		return nil, errors.Wrap(err, "unable to read byte order magic")
	}
	if n != len(bomBytes) {
		return nil, errors.New("insufficient data to read byte order magic")
	}

	if binary.BigEndian.Uint32(bomBytes[:]) == byteOrderMagic {
		r.endian = binary.BigEndian
	} else if binary.LittleEndian.Uint32(bomBytes[:]) == byteOrderMagic {
		r.endian = binary.LittleEndian
	} else {
		return nil, errors.New("unable to detect byte order")
	}

	// we can use "endianness independent" Read() function only above here
	r.er.endian = r.endian
	btl := r.endian.Uint32(btlBytes[:])

	bodyBytes := make([]byte, btl-16)
	n, err = r.er.Read(bodyBytes)
	if err != nil {
		return nil, errors.Wrap(err, "unable to read section header block body")
	}
	if n != len(bodyBytes) {
		return nil, errors.New("insufficient data to read section header block body")
	}

	btlTail, err := r.er.readUint32()
	if err != nil {
		return nil, errors.New("unable to read block total length at bottom of the block")
	}
	if btl != btlTail {
		return nil, errors.Errorf("block total length fields are not matched: begin == %d, end == %d", btl, btlTail)
	}

	return r.parseSectionHeaderBlockBody(btl, r.endian, bodyBytes)
}

func (r *Reader) parseSectionHeaderBlockBody(blockTotalLength uint32, byteOrder binary.ByteOrder, bodyBytes []byte) (*SectionHeaderBlock, error) {
	br := newEndiannessAwareReader(r.endian, bytes.NewReader(bodyBytes))
	major, err := br.readUint16()
	if err != nil {
		return nil, errors.Wrap(err, "unable to read major")
	}
	minor, err := br.readUint16()
	if err != nil {
		return nil, errors.Wrap(err, "unable to read minor")
	}
	sl, err := br.readInt64()
	if err != nil {
		return nil, errors.Wrap(err, "unable to read section length")
	}

	var opts SectionHeaderBlockOptions
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
		fmt.Printf("oc: %d, ol: %d\n", oc, ol)

		switch optioncode.OptionCode(oc) {
		case optioncode.EndOfOpt:
			break loop

		case optioncode.Comment:
			err := readCommonOptionComment(ol, br, &opts.Comments)
			if err != nil {
				return nil, err
			}

		case optioncode.CustomUTF8, optioncode.CustomUTF8WithoutNull, optioncode.CustomBinary, optioncode.CustomBinaryShouldNotCopied:
			err := readCustomOption(oc, ol, br, &opts.CustomOptions)
			if err != nil {
				return nil, err
			}

		case optioncode.SHB_Hardware:
			s, err := br.readString(uint(ol))
			if err != nil {
				return nil, errors.Wrap(err, "unable to read shb_hardware")
			}
			opts.Hardware = &s

		case optioncode.SHB_OS:
			s, err := br.readString(uint(ol))
			if err != nil {
				return nil, errors.Wrap(err, "unable to read shb_os")
			}
			opts.OS = &s

		case optioncode.SHB_UserAppl:
			s, err := br.readString(uint(ol))
			if err != nil {
				return nil, errors.Wrap(err, "unable to read shb_userappl")
			}
			opts.UserAppl = &s

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

	return &SectionHeaderBlock{
		BlockType:        blocktype.SectionHeader,
		BlockTotalLength: blockTotalLength,
		ByteOrderMagic:   byteOrderMagic,
		byteOrder:        byteOrder,
		MajorVersion:     major,
		MinorVersion:     minor,
		SectionLength:    sl,
		Options:          opts,
	}, nil
}
