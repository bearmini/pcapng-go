package pcapng

import (
	"bytes"
	"fmt"
	"net"
	"strings"

	"github.com/bearmini/pcapng-go/pcapng/blocktype"
	"github.com/bearmini/pcapng-go/pcapng/optioncode"
	"github.com/pkg/errors"
)

/*
4.5.  Name Resolution Block

   The Name Resolution Block (NRB) is used to support the correlation of
   numeric addresses (present in the captured packets) and their
   corresponding canonical names and it is optional.  Having the literal
   names saved in the file prevents the need for performing name
   resolution at a later time, when the association between names and
   addresses may be different from the one in use at capture time.
   Moreover, the NRB avoids the need for issuing a lot of DNS requests
   every time the trace capture is opened, and also provides name
   resolution when reading the capture with a machine not connected to
   the network.

   A Name Resolution Block is often placed at the beginning of the file,
   but no assumptions can be taken about its position.  Multiple NRBs
   can exist in a pcapng file, either due to memory constraints or
   because additional name resolutions were performed by file processing
   tools, like network analyzers.

   A Name Resolution Block need not contain any Records, except the
   nrb_record_end Record which MUST be the last Record.  The addresses
   and names in NRB Records MAY be repeated multiple times; i.e., the
   same IP address may resolve to multiple names, the same name may
   resolve to the multiple IP addresses, and even the same address-to-
   name pair may appear multiple times, in the same NRB or across NRBs.

   The format of the Name Resolution Block is shown in Figure 13.

       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +---------------------------------------------------------------+
    0 |                    Block Type = 0x00000004                    |
      +---------------------------------------------------------------+
    4 |                      Block Total Length                       |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    8 |      Record Type              |      Record Value Length      |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   12 /                       Record Value                            /
      /              variable length, padded to 32 bits               /
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      .                                                               .
      .                  . . . other records . . .                    .
      .                                                               .
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |  Record Type = nrb_record_end |   Record Value Length = 0     |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      /                                                               /
      /                      Options (variable)                       /
      /                                                               /
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                      Block Total Length                       |
      +---------------------------------------------------------------+

                  Figure 13: Name Resolution Block Format

   The Name Resolution Block has the following fields:

   o  Block Type: The block type of the Name Resolution Block is 4.

   o  Block Total Length: total size of this block, as described in
      Section 3.1.

   This is followed by zero or more Name Resolution Records (in the TLV
   format), each of which contains an association between a network
   address and a name.  An nrb_record_end MUST be added after the last
   Record, and MUST exist even if there are no other Records in the NRB.
   There are currently three possible types of records:

                  +-----------------+--------+----------+
                  | Name            | Code   | Length   |
                  +-----------------+--------+----------+
                  | nrb_record_end  | 0x0000 | 0        |
                  | nrb_record_ipv4 | 0x0001 | Variable |
                  | nrb_record_ipv6 | 0x0002 | Variable |
                  +-----------------+--------+----------+

                  Table 5: Name Resolution Block Records

   nrb_record_end:
           The nrb_record_end record delimits the end of name resolution
           records.  This record is needed to determine when the list of
           name resolution records has ended and some options (if any)
           begin.

   nrb_record_ipv4:
           The nrb_record_ipv4 record specifies an IPv4 address
           (contained in the first 4 octets), followed by one or more
           zero-terminated UTF-8 strings containing the DNS entries for
           that address.  The minimum valid Record Length for this
           Record Type is thus 6: 4 for the IP octets, 1 character, and
           a zero-value octet terminator.  Note that the IP address is
           treated as four octets, one for each octet of the IP address;
           it is not a 32-bit word, and thus the endianness of the SHB
           does not affect this field's value.

           Example: '127 0 0 1'"localhost".

           [Open issue: is an empty string (i.e., just a zero-value
           octet) valid?]

   nrb_record_ipv6:
           The nrb_record_ipv6 record specifies an IPv6 address
           (contained in the first 16 octets), followed by one or more
           zero-terminated strings containing the DNS entries for that
           address.  The minimum valid Record Length for this Record
           Type is thus 18: 16 for the IP octets, 1 character, and a
           zero-value octet terminator.

           Example: '20 01 0d b8 00 00 00 00 00 00 00 00 12 34 56
           78'"somehost".

           [Open issue: is an empty string (i.e., just a zero-value
           octet) valid?]

   Record Types other than those specified earlier MUST be ignored and
   skipped past.  More Record Types will likely be defined in the
   future, and MUST NOT break backwards compatibility.

   Each Record Value is aligned to and padded to a 32-bit boundary.  The
   corresponding Record Value Length reflects the actual length of the
   Record Value; it does not include the lengths of the Record Type
   field, the Record Value Length field, any padding for the Record
   Value, or anything after the Record Value.  For Record Types with
   name strings, the Record Length does include the zero-value octet
   terminating that string.  A Record Length of 0 is valid, unless
   indicated otherwise.

   After the list of Name Resolution Records, optionally, a list of
   options (formatted according to the rules defined in Section 3.5) can
   be present.

   In addition to the options defined in Section 3.5, the following
   options are valid within this block:

          +---------------+------+----------+-------------------+
          | Name          | Code | Length   | Multiple allowed? |
          +---------------+------+----------+-------------------+
          | ns_dnsname    | 2    | Variable | no                |
          | ns_dnsIP4addr | 3    | 4        | no                |
          | ns_dnsIP6addr | 4    | 16       | no                |
          +---------------+------+----------+-------------------+

                  Table 6: Name Resolution Block Options

   ns_dnsname:
           The ns_dnsname option is a UTF-8 string containing the name
           of the machine (DNS server) used to perform the name
           resolution.

           Example: "our_nameserver".

   ns_dnsIP4addr:
           The ns_dnsIP4addr option specifies the IPv4 address of the
           DNS server.  Note that the IP address is treated as four
           octets, one for each octet of the IP address; it is not a
           32-bit word, and thus the endianness of the SHB does not
           affect this field's value.

           Example: '192 168 0 1'.

   ns_dnsIP6addr:
           The ns_dnsIP6addr option specifies the IPv6 address of the
           DNS server.

           Example: '20 01 0d b8 00 00 00 00 00 00 00 00 12 34 56 78'.

*/

type NameResolutionBlock struct {
	BlockType        blocktype.BlockType
	BlockTotalLength uint32
	Records          []Record
	Options          NameResolutionBlockOptions
}

type Record struct {
	RecordType        RecordType
	RecordValueLength uint16
	RecordValue       RecordValue
}

type RecordValue struct {
	IP   net.IP
	Name string
}

func parseRecordValue(rt RecordType, b []byte) (RecordValue, error) {
	switch rt {
	case RecordTypeIPv4:
		if len(b) < 6 {
			return RecordValue{}, errors.New("invalid ipv4 record value length")
		}
		return RecordValue{
			IP:   net.IP(b[0:4]),
			Name: string(b[4:]),
		}, nil
	case RecordTypeIPv6:
		if len(b) < 18 {
			return RecordValue{}, errors.New("invalid ipv6 record value length")
		}
		return RecordValue{
			IP:   net.IP(b[0:16]),
			Name: string(b[16:]),
		}, nil
	default:
		return RecordValue{}, errors.New("unknown record type")
	}
}

func (r Record) String() string {
	t := r.RecordType
	l := r.RecordValueLength
	v := r.RecordValue
	return fmt.Sprintf("type:%s len:%d, value:%s (%s)", t, l, v.IP.String(), v.Name)
}

type RecordType uint16

const (
	RecordTypeEnd  RecordType = 0
	RecordTypeIPv4 RecordType = 1
	RecordTypeIPv6 RecordType = 2
)

func (t RecordType) String() string {
	switch t {
	case RecordTypeEnd:
		return "End"
	case RecordTypeIPv4:
		return "IPv4"
	case RecordTypeIPv6:
		return "IPv6"
	default:
		return "(Unknown)"
	}
}

type NameResolutionBlockOptions struct {
	DNSName       *string
	DNSIPv4Addr   *net.IP
	DNSIPv6Addr   *net.IP
	Comments      []string
	CustomOptions []CustomOption
}

func (o NameResolutionBlockOptions) String() string {
	options := make([]string, 0)
	if o.DNSName != nil {
		options = append(options, fmt.Sprintf("dnsname:%s", *o.DNSName))
	}
	if o.DNSIPv4Addr != nil {
		options = append(options, fmt.Sprintf("dnsIP4addr:%s", *o.DNSIPv4Addr))
	}
	if o.DNSIPv6Addr != nil {
		options = append(options, fmt.Sprintf("dnsIP6addr:%s", *o.DNSIPv6Addr))
	}

	return strings.Join(options, ",")
}

func (b *NameResolutionBlock) GetType() blocktype.BlockType {
	return b.BlockType
}

func (b *NameResolutionBlock) String() string {
	records := make([]string, 0)
	for _, r := range b.Records {
		records = append(records, r.String())
	}

	return fmt.Sprintf("%s block_len:%d records:[%s] options:{%s}",
		b.BlockType.String(), b.BlockTotalLength, strings.Join(records, ","), b.Options.String())
}

func (r *Reader) parseNameResolutionBlock(blockTotalLength uint32, bodyBytes []byte) (*NameResolutionBlock, error) {
	br := newEndiannessAwareReader(r.endian, bytes.NewReader(bodyBytes))

	records := make([]Record, 0)
records_loop:
	for {
		rtv, err := br.readUint16()
		if err != nil {
			return nil, errors.Wrap(err, "unable to read record type")
		}
		rt := RecordType(rtv)

		rl, err := br.readUint16()
		if err != nil {
			return nil, errors.Wrap(err, "unable to read record length")
		}

		if rt == RecordTypeEnd {
			break records_loop
		}

		rvb, err := br.readBytes(uint(rl))
		if err != nil {
			return nil, errors.Wrap(err, "unable to read record value")
		}

		rv, err := parseRecordValue(rt, rvb)
		if err != nil {
			return nil, errors.Wrap(err, "unable to parse record value")
		}

		records = append(records, Record{
			RecordType:        rt,
			RecordValueLength: rl,
			RecordValue:       rv,
		})

		// read padding
		padLen := 4 - (ol & 0x3)
		_, err = br.readBytes(uint(padLen))
		if err != nil {
			return nil, errors.Wrap(err, "unable to read padding in an option value")
		}
	}

	var opts NameResolutionBlockOptions
options_loop:
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
			break options_loop

		case optioncode.Comment:
			readCommonOptionComment(ol, br, &opts.Comments)

		case optioncode.CustomUTF8, optioncode.CustomUTF8WithoutNull, optioncode.CustomBinary, optioncode.CustomBinaryShouldNotCopied:
			err := readCustomOption(oc, ol, br, &opts.CustomOptions)
			if err != nil {
				return nil, err
			}

		case optioncode.NS_DNSName:
			ov, err := br.readBytes(uint(ol))
			if err != nil {
				return nil, errors.Wrap(err, "unable to read ns_dnsname")
			}
			name := string(ov)
			opts.DNSName = &name

		case optioncode.NS_DNSIP4Addr:
			if ol != 4 {
				return nil, errors.New("invalid option length for ns_dnsIP4addr")
			}
			ov, err := br.readBytes(4)
			if err != nil {
				return nil, errors.Wrap(err, "unable to read ns_dnsIP4addr")
			}
			ipv4 := net.IP(ov)
			opts.DNSIPv4Addr = &ipv4

		case optioncode.NS_DNSIP6Addr:
			if ol != 16 {
				return nil, errors.New("invalid option length for ns_dnsIP6addr")
			}
			ov, err := br.readBytes(16)
			if err != nil {
				return nil, errors.Wrap(err, "unable to read ns_dnsIP6addr")
			}
			ipv6 := net.IP(ov)
			opts.DNSIPv6Addr = &ipv6

		default:
			_, err := br.readBytes(uint(ol))
			if err != nil {
				return nil, errors.Wrapf(err, "unable to read unknown option (%d)", oc)
			}
		}

		// read padding
		padLen := ol & 0x3
		_, err = br.readBytes(uint(padLen))
		if err != nil {
			return nil, errors.Wrap(err, "unable to read padding in an option value")
		}
	}

	return &NameResolutionBlock{
		BlockType:        blocktype.NameResolution,
		BlockTotalLength: blockTotalLength,
		Records:          records,
		Options:          opts,
	}, nil
}
