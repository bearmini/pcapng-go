//go:generate stringer -type=BlockType -output=block_type_string.go
package blocktype

/*
From draft-tuexen-opsawg-pcapng November 13, 2017

3.2.  Block Types

   The currently standardized Block Type codes are specified in
   Section 11.1; they have been grouped in the following four
   categories:

   The following MANDATORY block MUST appear at least once in each file:

   o  Section Header Block (Section 4.1): it defines the most important
      characteristics of the capture file.

   The following OPTIONAL blocks MAY appear in a file:

   o  Interface Description Block (Section 4.2): it defines the most
      important characteristics of the interface(s) used for capturing
      traffic.  This block is required in certain cases, as described
      later.

   o  Enhanced Packet Block (Section 4.3): it contains a single captured
      packet, or a portion of it.  It represents an evolution of the
      original, now obsolete, Packet Block (Appendix A).  If this
      appears in a file, an Interface Description Block is also
      required, before this block.

   o  Simple Packet Block (Section 4.4): it contains a single captured
      packet, or a portion of it, with only a minimal set of information
      about it.  If this appears in a file, an Interface Description
      Block is also required, before this block.

   o  Name Resolution Block (Section 4.5): it defines the mapping from
      numeric addresses present in the packet capture and the canonical
      name counterpart.

   o  Interface Statistics Block (Section 4.6): it defines how to store
      some statistical data (e.g. packet dropped, etc) which can be
      useful to understand the conditions in which the capture has been
      made.  If this appears in a file, an Interface Description Block
      is also required, before this block.

   o  Custom Block (Section 4.7): it contains vendor-specific data in a
      portable fashion.

   The following OBSOLETE block SHOULD NOT appear in newly written files
   (but is documented in the Appendix for reference):

   o  Packet Block (Appendix A): it contains a single captured packet,
      or a portion of it.  It is OBSOLETE, and superseded by the
      Enhanced Packet Block (Section 4.3).

   The following EXPERIMENTAL blocks are considered interesting but the
   authors believe that they deserve more in-depth discussion before
   being defined:

   o  Alternative Packet Blocks

   o  Compression Block

   o  Encryption Block

   o  Fixed Length Block

   o  Directory Block

   o  Traffic Statistics and Monitoring Blocks

   o  Event/Security Blocks


   11.1.  Standardized Block Type Codes

   Every Block is uniquely identified by a 32-bit integer value, stored
   in the Block Header.

   As pointed out in Section 3.1, Block Type codes whose Most
   Significant Bit (bit 31) is set to 1 are reserved for local use by
   the application.

   All the remaining Block Type codes (0x00000000 to 0x7FFFFFFF) are
   standardized by this document.  Requests for new Block Type codes
   should be sent to the pcap- ng-format mailing list [6].

   The following is a list of the Standardized Block Type Codes:

   +-----------------------+-------------------------------------------+
   | Block Type Code       | Description                               |
   +-----------------------+-------------------------------------------+
   | 0x00000000            | Reserved ???                              |
   | 0x00000001            | Interface Description Block (Section 4.2) |
   | 0x00000002            | Packet Block (Appendix A)                 |
   | 0x00000003            | Simple Packet Block (Section 4.4)         |
   | 0x00000004            | Name Resolution Block (Section 4.5)       |
   | 0x00000005            | Interface Statistics Block (Section 4.6)  |
   | 0x00000006            | Enhanced Packet Block (Section 4.3)       |
   | 0x00000007            | IRIG Timestamp Block (requested by        |
   |                       | Gianluca Varenni                          |
   |                       | <gianluca.varenni@cacetech.com>, CACE     |
   |                       | Technologies LLC)                         |
   | 0x00000008            | ARINC 429 [7] in AFDX Encapsulation       |
   |                       | Information Block (requested by Gianluca  |
   |                       | Varenni <gianluca.varenni@cacetech.com>,  |
   |                       | CACE Technologies LLC)                    |
   | 0x00000BAD            | Custom Block that rewriters can copy into |
   |                       | new files (Section 4.7)                   |
   | 0x40000BAD            | Custom Block that rewriters should not    |
   |                       | copy into new files (Section 4.7)         |
   | 0x0A0D0D0A            | Section Header Block (Section 4.1)        |
   | 0x0A0D0A00-0x0A0D0AFF | Reserved. Used to detect trace files      |
   |                       | corrupted because of file transfers using |
   |                       | the HTTP protocol in text mode.           |
   | 0x000A0D0A-0xFF0A0D0A | Reserved. Used to detect trace files      |
   |                       | corrupted because of file transfers using |
   |                       | the HTTP protocol in text mode.           |
   | 0x000A0D0D-0xFF0A0D0D | Reserved. Used to detect trace files      |
   |                       | corrupted because of file transfers using |
   |                       | the HTTP protocol in text mode.           |
   | 0x0D0D0A00-0x0D0D0AFF | Reserved. Used to detect trace files      |
   |                       | corrupted because of file transfers using |
   |                       | the FTP protocol in text mode.            |
   | 0x80000000-0xFFFFFFFF | Reserved for local use.                   |
   +-----------------------+-------------------------------------------+

                  Table 8: Standardized Block Type Codes

   [Open issue: reserve 0x40000000-0x7FFFFFFF for do-not-copy-bit range
   of base types?]



*/
type BlockType uint32

const (
	SectionHeader        BlockType = 0x0a0d0d0a
	InterfaceDescription BlockType = 0x00000001
	SimplePacket         BlockType = 0x00000003
	NameResolution       BlockType = 0x00000004
	InterfaceStatistics  BlockType = 0x00000005
	EnhancedPacket       BlockType = 0x00000006
)
