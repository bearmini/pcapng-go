package pcapng

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/bearmini/pcapng-go/pcapng/blocktype"
	"github.com/bearmini/pcapng-go/pcapng/optioncode"
	"github.com/pkg/errors"
)

/*
4.6.  Interface Statistics Block

   The Interface Statistics Block (ISB) contains the capture statistics
   for a given interface and it is optional.  The statistics are
   referred to the interface defined in the current Section identified
   by the Interface ID field.  An Interface Statistics Block is normally
   placed at the end of the file, but no assumptions can be taken about
   its position - it can even appear multiple times for the same
   interface.

   The format of the Interface Statistics Block is shown in Figure 14.

       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +---------------------------------------------------------------+
    0 |                   Block Type = 0x00000005                     |
      +---------------------------------------------------------------+
    4 |                      Block Total Length                       |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    8 |                         Interface ID                          |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   12 |                        Timestamp (High)                       |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   16 |                        Timestamp (Low)                        |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   20 /                                                               /
      /                      Options (variable)                       /
      /                                                               /
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                      Block Total Length                       |
      +---------------------------------------------------------------+

               Figure 14: Interface Statistics Block Format

   The fields have the following meaning:

   o  Block Type: The block type of the Interface Statistics Block is 5.

   o  Block Total Length: total size of this block, as described in
      Section 3.1.

   o  Interface ID: specifies the interface these statistics refers to;
      the correct interface will be the one whose Interface Description
      Block (within the current Section of the file) is identified by
      same number (see Section 4.2) of this field.

   o  Timestamp: time this statistics refers to.  The format of the
      timestamp is the same already defined in the Enhanced Packet Block
      (Section 4.3).

   o  Options: optionally, a list of options (formatted according to the
      rules defined in Section 3.5) can be present.

   All the statistic fields are defined as options in order to deal with
   systems that do not have a complete set of statistics.  Therefore, In
   addition to the options defined in Section 3.5, the following options
   are valid within this block:

         +------------------+------+--------+-------------------+
         | Name             | Code | Length | Multiple allowed? |
         +------------------+------+--------+-------------------+
         | isb_starttime    | 2    | 8      | no                |
         | isb_endtime      | 3    | 8      | no                |
         | isb_ifrecv       | 4    | 8      | no                |
         | isb_ifdrop       | 5    | 8      | no                |
         | isb_filteraccept | 6    | 8      | no                |
         | isb_osdrop       | 7    | 8      | no                |
         | isb_usrdeliv     | 8    | 8      | no                |
         +------------------+------+--------+-------------------+

                Table 7: Interface Statistics Block Options

   isb_starttime:
           The isb_starttime option specifies the time the capture
           started; time will be stored in two blocks of four octets
           each.  The format of the timestamp is the same as the one
           defined in the Enhanced Packet Block (Section 4.3).

           Example: '97 c3 04 00 aa 47 ca 64' in Little Endian, decodes
           to 06/29/2012 06:16:50 UTC.

   isb_endtime:
           The isb_endtime option specifies the time the capture ended;
           time will be stored in two blocks of four octets each.  The
           format of the timestamp is the same as the one defined in the
           Enhanced Packet Block (Section 4.3).

           Example: '96 c3 04 00 73 89 6a 65', in Little Endian, decodes
           to 06/29/2012 06:17:00 UTC.

   isb_ifrecv:
           The isb_ifrecv option specifies the 64-bit unsigned integer
           number of packets received from the physical interface
           starting from the beginning of the capture.

           Example: the decimal number 100.

   isb_ifdrop:
           The isb_ifdrop option specifies the 64-bit unsigned integer
           number of packets dropped by the interface due to lack of
           resources starting from the beginning of the capture.

           Example: '0'.

   isb_filteraccept:
           The isb_filteraccept option specifies the 64-bit unsigned
           integer number of packets accepted by filter starting from
           the beginning of the capture.

           Example: the decimal number 100.

   isb_osdrop:
           The isb_osdrop option specifies the 64-bit unsigned integer
           number of packets dropped by the operating system starting
           from the beginning of the capture.

           Example: '0'.

   isb_usrdeliv:
           The isb_usrdeliv option specifies the 64-bit unsigned integer
           number of packets delivered to the user starting from the
           beginning of the capture.  The value contained in this field
           can be different from the value 'isb_filteraccept -
           isb_osdrop' because some packets could still be in the OS
           buffers when the capture ended.

           Example: '0'.

   All the fields that refer to packet counters are 64-bit values,
   represented with the octet order of the current section.  Special
   care must be taken in accessing these fields: since all the blocks
   are aligned to a 32-bit boundary, such fields are not guaranteed to
   be aligned on a 64-bit boundary.
*/

type InterfaceStatisticsBlock struct {
	BlockType        blocktype.BlockType
	BlockTotalLength uint32
	InterfaceID      uint32
	TimestampHigh    uint32
	TimestampLow     uint32
	Options          InterfaceStatisticsBlockOptions
}

func (b *InterfaceStatisticsBlock) GetType() blocktype.BlockType {
	return b.BlockType
}

func (b *InterfaceStatisticsBlock) String() string {
	return fmt.Sprintf("%s block_len:%d if_id:%d ts_hi:%d ts_lo:%d options:{%s}",
		b.BlockType.String(), b.BlockTotalLength, b.InterfaceID, b.TimestampHigh, b.TimestampLow, b.Options.String())
}

type InterfaceStatisticsBlockOptions struct {
	StartTime     *uint64
	EndTime       *uint64
	IFRecv        *uint64
	IFDrop        *uint64
	FilterAccept  *uint64
	OSDrop        *uint64
	UsrDeliv      *uint64
	Comments      []string
	CustomOptions []CustomOption
}

func (o InterfaceStatisticsBlockOptions) String() string {
	options := make([]string, 0)
	if o.StartTime != nil {
		options = append(options, fmt.Sprintf("start_time:%s", *o.StartTime))
	}
	if o.EndTime != nil {
		options = append(options, fmt.Sprintf("end_time:%s", *o.EndTime))
	}
	if o.IFRecv != nil {
		options = append(options, fmt.Sprintf("if_recv:%d", *o.IFRecv))
	}
	if o.IFDrop != nil {
		options = append(options, fmt.Sprintf("if_drop:%d", *o.IFDrop))
	}
	if o.FilterAccept != nil {
		options = append(options, fmt.Sprintf("filter_accept:%d", *o.FilterAccept))
	}
	if o.OSDrop != nil {
		options = append(options, fmt.Sprintf("os_drop:%d", *o.OSDrop))
	}
	if o.UsrDeliv != nil {
		options = append(options, fmt.Sprintf("usr_deliv:%d", *o.UsrDeliv))
	}

	return strings.Join(options, ",")
}

func (r *Reader) parseInterfaceStatisticsBlock(blockTotalLength uint32, bodyBytes []byte) (*InterfaceStatisticsBlock, error) {
	br := newEndiannessAwareReader(r.endian, bytes.NewReader(bodyBytes))
	ifid, err := br.readUint32()
	if err != nil {
		return nil, errors.Wrap(err, "unable to read interface id")
	}
	tshi, err := br.readUint32()
	if err != nil {
		return nil, errors.Wrap(err, "unable to read timestamp hi")
	}
	tslo, err := br.readUint32()
	if err != nil {
		return nil, errors.Wrap(err, "unable to read timestamp lo")
	}

	var opts InterfaceStatisticsBlockOptions
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

		case optioncode.ISB_StartTime:
			ov, err := br.readUint64()
			if err != nil {
				return nil, errors.Wrap(err, "unable to read isb_starttime")
			}
			opts.StartTime = &ov

		case optioncode.ISB_EndTime:
			ov, err := br.readUint64()
			if err != nil {
				return nil, errors.Wrap(err, "unable to read isb_endtime")
			}
			opts.EndTime = &ov

		case optioncode.ISB_IFRecv:
			ov, err := br.readUint64()
			if err != nil {
				return nil, errors.Wrap(err, "unable to read isb_ifrecv")
			}
			opts.IFRecv = &ov

		case optioncode.ISB_IFDrop:
			ov, err := br.readUint64()
			if err != nil {
				return nil, errors.Wrap(err, "unable to read isb_ifdrop")
			}
			opts.IFDrop = &ov

		case optioncode.ISB_FilterAccept:
			ov, err := br.readUint64()
			if err != nil {
				return nil, errors.Wrap(err, "unable to read isb_filteraccept")
			}
			opts.FilterAccept = &ov

		case optioncode.ISB_OSDrop:
			ov, err := br.readUint64()
			if err != nil {
				return nil, errors.Wrap(err, "unable to read isb_osdrop")
			}
			opts.OSDrop = &ov

		case optioncode.ISB_UsrDeliv:
			ov, err := br.readUint64()
			if err != nil {
				return nil, errors.Wrap(err, "unable to read isb_usrdeliv")
			}
			opts.UsrDeliv = &ov

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

	return &InterfaceStatisticsBlock{
		BlockType:        blocktype.InterfaceStatistics,
		BlockTotalLength: blockTotalLength,
		InterfaceID:      ifid,
		TimestampHigh:    tshi,
		TimestampLow:     tslo,
		Options:          opts,
	}, nil
}
