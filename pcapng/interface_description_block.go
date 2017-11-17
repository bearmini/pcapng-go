package pcapng

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"strings"

	"github.com/bearmini/pcapng-go/pcapng/blocktype"
	"github.com/bearmini/pcapng-go/pcapng/linktype"
	"github.com/bearmini/pcapng-go/pcapng/optioncode"
	"github.com/pkg/errors"
)

/*
4.2.  Interface Description Block

   An Interface Description Block (IDB) is the container for information
   describing an interface on which packet data is captured.

   Tools that write / read the capture file associate an incrementing
   32-bit number (starting from '0') to each Interface Definition Block,
   called the Interface ID for the interface in question.  This number
   is unique within each Section and identifies the interface to which
   the IDB refers; it is only unique inside the current section, so, two
   Sections can have different interfaces identified by the same
   Interface ID values.  This unique identifier is referenced by other
   blocks, such as Enhanced Packet Blocks and Interface Statistic
   Blocks, to indicate the interface to which the block refers (such the
   interface that was used to capture the packet that an Enhanced Packet
   Block contains or to which the statistics in an Interface Statistic
   Block refer).

   There must be an Interface Description Block for each interface to
   which another block refers.  Blocks such as an Enhanced Packet Block
   or an Interface Statistics Block contain an Interface ID value
   referring to a particular interface, and a Simple Packet Block
   implicitly refers to an interface with an Interface ID of 0.  If the
   file does not contain any blocks that use an Interface ID, then the
   file does not need to have any IDBs.

   An Interface Description Block is valid only inside the section to
   which it belongs.  The structure of a Interface Description Block is
   shown in Figure 10.

       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +---------------------------------------------------------------+
    0 |                    Block Type = 0x00000001                    |
      +---------------------------------------------------------------+
    4 |                      Block Total Length                       |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    8 |           LinkType            |           Reserved            |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   12 |                            SnapLen                            |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   16 /                                                               /
      /                      Options (variable)                       /
      /                                                               /
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                      Block Total Length                       |
      +---------------------------------------------------------------+

               Figure 10: Interface Description Block Format

   The meaning of the fields is:

   o  Block Type: The block type of the Interface Description Block is
      1.

   o  Block Total Length: total size of this block, as described in
      Section 3.1.

   o  LinkType: a value that defines the link layer type of this
      interface.  The list of Standardized Link Layer Type codes is
      available in the tcpdump.org link-layer header types registry [1].

   o  Reserved: not used - MUST be filled with 0, and ignored by pcapng
      file readers.

   o  SnapLen: maximum number of octets captured from each packet.  The
      portion of each packet that exceeds this value will not be stored
      in the file.  A value of zero indicates no limit.

   o  Options: optionally, a list of options (formatted according to the
      rules defined in Section 3.5) can be present.

   In addition to the options defined in Section 3.5, the following
   options are valid within this block:

         +----------------+------+----------+-------------------+
         | Name           | Code | Length   | Multiple allowed? |
         +----------------+------+----------+-------------------+
         | if_name        | 2    | Variable | no                |
         | if_description | 3    | Variable | no                |
         | if_IPv4addr    | 4    | 8        | yes               |
         | if_IPv6addr    | 5    | 17       | yes               |
         | if_MACaddr     | 6    | 6        | no                |
         | if_EUIaddr     | 7    | 8        | no                |
         | if_speed       | 8    | 8        | no                |
         | if_tsresol     | 9    | 1        | no                |
         | if_tzone       | 10   | 4        | no                |
         | if_filter      | 11   | variable | no                |
         | if_os          | 12   | variable | no                |
         | if_fcslen      | 13   | 1        | no                |
         | if_tsoffset    | 14   | 8        | no                |
         +----------------+------+----------+-------------------+

               Table 3: Interface Description Block Options

   if_name:
           The if_name option is a UTF-8 string containing the name of
           the device used to capture data.

           Examples: "eth0",
           "\Device\NPF_{AD1CE675-96D0-47C5-ADD0-2504B9126B68}".

   if_description:
           The if_description option is a UTF-8 string containing the
           description of the device used to capture data.

           Examples: "Broadcom NetXtreme", "First Ethernet Interface".

   if_IPv4addr:
           The if_IPv4addr option is an IPv4 network address and
           corresponding netmask for the interface.  The first four
           octets are the IP address, and the next four octets are the
           netmask.  This option can be repeated multiple times within
           the same Interface Description Block when multiple IPv4
           addresses are assigned to the interface.  Note that the IP
           address and netmask are both treated as four octets, one for
           each octet of the address or mask; they are not 32-bit
           numbers, and thus the endianness of the SHB does not affect
           this field's value.

           Examples: '192 168 1 1 255 255 255 0'.

   if_IPv6addr:
           The if_IPv6addr option is an IPv6 network address and
           corresponding prefix length for the interface.  The first 16
           octets are the IP address and the next octet is the prefix
           length.  This option can be repeated multiple times within
           the same Interface Description Block when multiple IPv6
           addresses are assigned to the interface.

           Example: 2001:0db8:85a3:08d3:1319:8a2e:0370:7344/64 is
           written (in hex) as '20 01 0d b8 85 a3 08 d3 13 19 8a 2e 03
           70 73 44 40'.

   if_MACaddr:
           The if_MACaddr option is the Interface Hardware MAC address
           (48 bits), if available.

           Example: '00 01 02 03 04 05'.

   if_EUIaddr:
           The if_EUIaddr option is the Interface Hardware EUI address
           (64 bits), if available.

           Example: '02 34 56 FF FE 78 9A BC'.

   if_speed:
           The if_speed option is a 64-bit number for the Interface
           speed (in bits per second).

           Example: the 64-bit decimal number 100000000 for 100Mbps.

   if_tsresol:
           The if_tsresol option identifies the resolution of
           timestamps.  If the Most Significant Bit is equal to zero,
           the remaining bits indicates the resolution of the timestamp
           as a negative power of 10 (e.g. 6 means microsecond
           resolution, timestamps are the number of microseconds since
           1970-01-01 00:00:00 UTC).  If the Most Significant Bit is
           equal to one, the remaining bits indicates the resolution as
           as negative power of 2 (e.g. 10 means 1/1024 of second).  If
           this option is not present, a resolution of 10^-6 is assumed
           (i.e. timestamps have the same resolution of the standard
           'libpcap' timestamps).

           Example: '6'.

   if_tzone:
           The if_tzone option identifies the time zone for GMT support
           (TODO: specify better).

           Example: TODO: give a good example.

   if_filter:
           The if_filter option identifies the filter (e.g. "capture
           only TCP traffic") used to capture traffic.  The first octet
           of the Option Data keeps a code of the filter used (e.g. if
           this is a libpcap string, or BPF bytecode, and more).  More
           details about this format will be presented in Appendix XXX
           (TODO).  (TODO: better use different options for different
           fields? e.g. if_filter_pcap, if_filter_bpf, ...)

           Example: '00'"tcp port 23 and host 192.0.2.5".

   if_os:
           The if_os option is a UTF-8 string containing the name of the
           operating system of the machine in which this interface is
           installed.  This can be different from the same information
           that can be contained by the Section Header Block
           (Section 4.1) because the capture can have been done on a
           remote machine.

           Examples: "Windows XP SP2", "openSUSE 10.2".

   if_fcslen:
           The if_fcslen option is an 8-bit unsigned integer value that
           specifies the length of the Frame Check Sequence (in bits)
           for this interface.  For link layers whose FCS length can
           change during time, the Enhanced Packet Block epb_flags
           Option can be used in each Enhanced Packet Block (see
           Section 4.3.1).

           Example: '4'.

   if_tsoffset:
           The if_tsoffset option is a 64-bit integer value that
           specifies an offset (in seconds) that must be added to the
           timestamp of each packet to obtain the absolute timestamp of
           a packet.  If the option is missing, the timestamps stored in
           the packet MUST be considered absolute timestamps.  The time
           zone of the offset can be specified with the option if_tzone.
           TODO: won't a if_tsoffset_low for fractional second offsets
           be useful for highly synchronized capture systems?

           Example: '1234'.

*/

type InterfaceDescriptionBlock struct {
	BlockType        blocktype.BlockType
	BlockTotalLength uint32
	LinkType         linktype.LinkType
	SnapLen          uint32
	Options          InterfaceDescriptionBlockOptions
}

func (b *InterfaceDescriptionBlock) GetType() blocktype.BlockType {
	return b.BlockType
}

func (b *InterfaceDescriptionBlock) String() string {
	return fmt.Sprintf("%s block_len:%d link_type:%s snap_len:%d options:{%s}",
		b.BlockType.String(), b.BlockTotalLength, b.LinkType.String(), b.SnapLen, b.Options.String())
}

type InterfaceDescriptionBlockOptions struct {
	Name          *string
	Description   *string
	IPv4Addr      []IPv4AddrInfo
	IPv6Addr      []IPv6AddrInfo
	MACAddr       []net.HardwareAddr
	EUIAddr       []net.HardwareAddr
	Speed         *uint64
	TSResol       *int8
	TZone         *int32
	Filter        []byte
	OS            *string
	FCSLen        *uint8
	TSOffset      *int64
	Comments      []string
	CustomOptions []CustomOption
}

type IPv4AddrInfo struct {
	IPv4Addr net.IP
	NetMask  net.IPMask
}

func (i *IPv4AddrInfo) String() string {
	return fmt.Sprintf("addr:%s, mask:%s", i.IPv4Addr.String(), i.NetMask.String())
}

type IPv6AddrInfo struct {
	IPv6Addr     net.IP
	PrefixLength uint8
}

func (i *IPv6AddrInfo) String() string {
	return fmt.Sprintf("addr:%s/%d", i.IPv6Addr.String(), i.PrefixLength)
}

func (o *InterfaceDescriptionBlockOptions) String() string {
	options := make([]string, 0)
	if o.Name != nil {
		options = append(options, fmt.Sprintf("name:%s", *o.Name))
	}
	if o.Description != nil {
		options = append(options, fmt.Sprintf("description:%s", *o.Description))
	}
	if o.IPv4Addr != nil {
		a := make([]string, 0)
		for _, addr := range o.IPv4Addr {
			a = append(a, addr.String())
		}
		options = append(options, fmt.Sprintf("ipv4:[%s]", strings.Join(a, ",")))
	}
	if o.IPv6Addr != nil {
		a := make([]string, 0)
		for _, addr := range o.IPv6Addr {
			a = append(a, addr.String())
		}
		options = append(options, fmt.Sprintf("ipv6:[%s]", strings.Join(a, ",")))
	}
	if o.MACAddr != nil {
		a := make([]string, 0)
		for _, addr := range o.MACAddr {
			a = append(a, addr.String())
		}
		options = append(options, fmt.Sprintf("mac:[%s]", strings.Join(a, ",")))
	}
	if o.EUIAddr != nil {
		a := make([]string, 0)
		for _, addr := range o.EUIAddr {
			a = append(a, addr.String())
		}
		options = append(options, fmt.Sprintf("eui:[%s]", strings.Join(a, ",")))
	}
	if o.Speed != nil {
		options = append(options, fmt.Sprintf("speed:%d", *o.Speed))
	}
	if o.TSResol != nil {
		options = append(options, fmt.Sprintf("tsresol:%d", *o.TSResol))
	}
	if o.TZone != nil {
		options = append(options, fmt.Sprintf("tzone:%d", *o.TZone))
	}
	if o.Filter != nil {
		options = append(options, fmt.Sprintf("filter:%s", hex.EncodeToString(o.Filter)))
	}
	if o.OS != nil {
		options = append(options, fmt.Sprintf("os:%s", *o.OS))
	}
	if o.FCSLen != nil {
		options = append(options, fmt.Sprintf("fcslen:%d", *o.FCSLen))
	}
	if o.TSOffset != nil {
		options = append(options, fmt.Sprintf("tsoffset:%d", *o.TSOffset))
	}

	return strings.Join(options, ",")
}

func (r *Reader) parseInterfaceDescriptionBlockBody(blockTotalLength uint32, bodyBytes []byte) (*InterfaceDescriptionBlock, error) {
	br := newEndiannessAwareReader(r.endian, bytes.NewReader(bodyBytes))
	lt, err := br.readUint16()
	if err != nil {
		return nil, errors.Wrap(err, "unable to read link type")
	}
	_, err = br.readUint16()
	if err != nil {
		return nil, errors.Wrap(err, "unable to read reserved")
	}
	sl, err := br.readUint32()
	if err != nil {
		return nil, errors.Wrap(err, "unable to read snap length")
	}

	var opts InterfaceDescriptionBlockOptions
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

		case optioncode.IF_Name:
			s, err := br.readString(uint(ol))
			if err != nil {
				return nil, errors.Wrap(err, "unable to read if_name")
			}
			opts.Name = &s

		case optioncode.IF_Description:
			s, err := br.readString(uint(ol))
			if err != nil {
				return nil, errors.Wrap(err, "unable to read if_description")
			}
			opts.Description = &s

		case optioncode.IF_IPv4Addr:
			if ol != 8 {
				return nil, errors.New("invalid option length for if_IPv4addr")
			}
			b, err := br.readBytes(uint(ol))
			if err != nil {
				return nil, errors.Wrap(err, "unable to read if_IPv4addr")
			}
			addr := net.IPv4(b[0], b[1], b[2], b[3])
			mask := net.IPv4Mask(b[4], b[5], b[6], b[7])
			if opts.IPv4Addr == nil {
				opts.IPv4Addr = make([]IPv4AddrInfo, 0)
			}
			opts.IPv4Addr = append(opts.IPv4Addr, IPv4AddrInfo{
				IPv4Addr: addr,
				NetMask:  mask,
			})

		case optioncode.IF_IPv6Addr:
			if ol != 17 {
				return nil, errors.New("invalid option length for if_IPv6addr")
			}
			b, err := br.readBytes(uint(ol))
			if err != nil {
				return nil, errors.Wrap(err, "unable to read if_IPv6addr")
			}
			addr := net.IP(b[0:16])
			prefix := uint8(b[16])
			if opts.IPv4Addr == nil {
				opts.IPv6Addr = make([]IPv6AddrInfo, 0)
			}
			opts.IPv6Addr = append(opts.IPv6Addr, IPv6AddrInfo{
				IPv6Addr:     addr,
				PrefixLength: prefix,
			})

		case optioncode.IF_MACAddr:
			if ol != 6 {
				return nil, errors.New("invalid option length for if_MACaddr")
			}
			b, err := br.readBytes(uint(ol))
			if err != nil {
				return nil, errors.Wrap(err, "unable to read if_MACaddr")
			}
			addr := net.HardwareAddr(b)
			if opts.MACAddr == nil {
				opts.MACAddr = make([]net.HardwareAddr, 0)
			}
			opts.MACAddr = append(opts.MACAddr, addr)

		case optioncode.IF_EUIAddr:
			if ol != 8 {
				return nil, errors.New("invalid option length for if_EUIaddr")
			}
			b, err := br.readBytes(uint(ol))
			if err != nil {
				return nil, errors.Wrap(err, "unable to read if_EUIaddr")
			}
			addr := net.HardwareAddr(b)
			if opts.EUIAddr == nil {
				opts.EUIAddr = make([]net.HardwareAddr, 0)
			}
			opts.EUIAddr = append(opts.EUIAddr, addr)

		case optioncode.IF_Speed:
			if ol != 8 {
				return nil, errors.New("invalid option length for if_speed")
			}
			speed, err := br.readUint64()
			if err != nil {
				return nil, errors.Wrap(err, "unable to read if_speed")
			}
			opts.Speed = &speed

		case optioncode.IF_TSResol:
			if ol != 1 {
				return nil, errors.New("invalid option length for if_tsresol")
			}
			tsresol, err := br.readInt8()
			if err != nil {
				return nil, errors.Wrap(err, "unable to read if_tsresol")
			}
			opts.TSResol = &tsresol

		case optioncode.IF_TZone:
			if ol != 4 {
				return nil, errors.New("invalid option length for if_tzone")
			}
			tzone, err := br.readInt32()
			if err != nil {
				return nil, errors.Wrap(err, "unable to read if_tzone")
			}
			opts.TZone = &tzone

		case optioncode.IF_Filter:
			b, err := br.readBytes(uint(ol))
			if err != nil {
				return nil, errors.Wrap(err, "unable to read if_filter")
			}
			opts.Filter = b

		case optioncode.IF_OS:
			s, err := br.readString(uint(ol))
			if err != nil {
				return nil, errors.Wrap(err, "unable to read if_os")
			}
			opts.OS = &s

		case optioncode.IF_FCSLen:
			if ol != 1 {
				return nil, errors.New("invalid option length for if_fcslen")
			}
			fl, err := br.readUint8()
			if err != nil {
				return nil, errors.Wrap(err, "unable to read if_tsresol")
			}
			opts.FCSLen = &fl

		case optioncode.IF_TSOffset:
			if ol != 8 {
				return nil, errors.New("invalid option length for if_tsoffset")
			}
			tso, err := br.readInt64()
			if err != nil {
				return nil, errors.Wrap(err, "unable to read if_tsoffset")
			}
			opts.TSOffset = &tso

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

	return &InterfaceDescriptionBlock{
		BlockType:        blocktype.InterfaceDescription,
		BlockTotalLength: blockTotalLength,
		LinkType:         linktype.LinkType(lt),
		SnapLen:          sl,
		Options:          opts,
	}, nil
}
