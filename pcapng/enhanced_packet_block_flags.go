package pcapng

/*
4.3.1.  Enhanced Packet Block Flags Word

   The Enhanced Packet Block Flags Word is a 32-bit value that contains
   link-layer information about the packet.

   The word is encoded as an unsigned 32-bit integer, using the
   endianness of the Section Header Block scope it is in.  In the
   following table, the bits are numbered with 0 being the most-
   significant bit and 31 being the least-significant bit of the 32-bit
   unsigned integer.  The meaning of the bits is the following:

   +--------+----------------------------------------------------------+
   | Bit    | Description                                              |
   | Number |                                                          |
   +--------+----------------------------------------------------------+
   | 0-1    | Inbound / Outbound packet (00 = information not          |
   |        | available, 01 = inbound, 10 = outbound)                  |
   | 2-4    | Reception type (000 = not specified, 001 = unicast, 010  |
   |        | = multicast, 011 = broadcast, 100 = promiscuous).        |
   | 5-8    | FCS length, in octets (0000 if this information is not   |
   |        | available).  This value overrides the if_fcslen option   |
   |        | of the Interface Description Block, and is used with     |
   |        | those link layers (e.g. PPP) where the length of the FCS |
   |        | can change during time.                                  |
   | 9-15   | Reserved (MUST be set to zero).                          |
   | 16-31  | link-layer-dependent errors (Bit 31 = symbol error, Bit  |
   |        | 30 = preamble error, Bit 29 = Start Frame Delimiter      |
   |        | error, Bit 28 = unaligned frame error, Bit 27 = wrong    |
   |        | Inter Frame Gap error, Bit 26 = packet too short error,  |
   |        | Bit 25 = packet too long error, Bit 24 = CRC error,      |
   |        | other?? are 16 bit enough?).                             |
	 +--------+----------------------------------------------------------+
*/

type EnhancedPacketBlockFlags struct {
	Bound                    Bound
	ReceptionType            ReceptionType
	FCSLength                uint8
	LinkLayerDependentErrors LinkLayerDependentErrors
}

func ParseEnhancedPacketBlockFlags(v uint32) EnhancedPacketBlockFlags {
	return EnhancedPacketBlockFlags{
		Bound:                    Bound(v & 0x00000003),
		ReceptionType:            ReceptionType((v & 0x0000001c) >> 2),
		FCSLength:                uint8((v & 0x000001e0) >> 5),
		LinkLayerDependentErrors: ParseLinkLayerDependentErrors(uint16((v & 0xffff0000) >> 16)),
	}
}

type Bound uint8

const (
	BoundUnknown Bound = iota
	Inbound
	Outbound
)

type ReceptionType uint8

const (
	ReceptionTypeNotSpecified ReceptionType = iota
	Unicast
	Multicast
	Broadcast
	Promiscuous
)

type LinkLayerDependentErrors struct {
	SymbolError              bool
	PreambleError            bool
	StartFrameDelimiterError bool
	UnalignedFrameError      bool
	WrongInterFrameGapError  bool
	PacketTooShortError      bool
	PacketTooLongError       bool
	CRCError                 bool
}

func ParseLinkLayerDependentErrors(flags uint16) LinkLayerDependentErrors {
	return LinkLayerDependentErrors{
		SymbolError:              flags&0x8000 != 0,
		PreambleError:            flags&0x4000 != 0,
		StartFrameDelimiterError: flags&0x2000 != 0,
		UnalignedFrameError:      flags&0x1000 != 0,
		WrongInterFrameGapError:  flags&0x0800 != 0,
		PacketTooShortError:      flags&0x0400 != 0,
		PacketTooLongError:       flags&0x0200 != 0,
		CRCError:                 flags&0x0100 != 0,
	}
}

func (e LinkLayerDependentErrors) Encode() uint16 {
	var se, pe, sfde, ufe, wifge, ptse, ptle, ce uint16
	if e.SymbolError {
		se = 1 << 15
	}
	if e.PreambleError {
		pe = 1 << 14
	}
	if e.StartFrameDelimiterError {
		sfde = 1 << 13
	}
	if e.UnalignedFrameError {
		ufe = 1 << 12
	}
	if e.WrongInterFrameGapError {
		wifge = 1 << 11
	}
	if e.PacketTooShortError {
		ptse = 1 << 10
	}
	if e.PacketTooLongError {
		ptle = 1 << 9
	}
	if e.CRCError {
		ce = 1 << 8
	}
	return se | pe | sfde | ufe | wifge | ptse | ptle | ce
}
