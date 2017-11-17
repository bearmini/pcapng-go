package optioncode

type OptionCode uint16

const (
	EndOfOpt OptionCode = 0
	Comment  OptionCode = 1

	// for Section Header Block
	SHB_Hardware OptionCode = 2
	SHB_OS       OptionCode = 3
	SHB_UserAppl OptionCode = 4

	// for Interface Description Block
	IF_Name        OptionCode = 2
	IF_Description OptionCode = 3
	IF_IPv4Addr    OptionCode = 4
	IF_IPv6Addr    OptionCode = 5
	IF_MACAddr     OptionCode = 6
	IF_EUIAddr     OptionCode = 7
	IF_Speed       OptionCode = 8
	IF_TSResol     OptionCode = 9
	IF_TZone       OptionCode = 10
	IF_Filter      OptionCode = 11
	IF_OS          OptionCode = 12
	IF_FCSLen      OptionCode = 13
	IF_TSOffset    OptionCode = 14

	// for Enhanced Packet Block
	EPB_Flags     OptionCode = 2
	EPB_Hash      OptionCode = 3
	EPB_DropCount OptionCode = 4

	// for Name Resolution Block
	NRB_RecordEnd  OptionCode = 0
	NRB_RecordIPv4 OptionCode = 1
	NRB_RecordIPv6 OptionCode = 2
	NS_DNSName     OptionCode = 2
	NS_DNSIP4Addr  OptionCode = 3
	NS_DNSIP6Addr  OptionCode = 4

	// for Interface Statistics Block
	ISB_StartTime    OptionCode = 2
	ISB_EndTime      OptionCode = 3
	ISB_IFRecv       OptionCode = 4
	ISB_IFDrop       OptionCode = 5
	ISB_FilterAccept OptionCode = 6
	ISB_OSDrop       OptionCode = 7
	ISB_UsrDeliv     OptionCode = 8

	CustomUTF8                  OptionCode = 2988
	CustomBinary                OptionCode = 2989
	CustomUTF8WithoutNull       OptionCode = 19372
	CustomBinaryShouldNotCopied OptionCode = 19373
)
