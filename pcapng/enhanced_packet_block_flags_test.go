package pcapng

import (
	"reflect"
	"testing"
)

func TestEnhancedPacketBlockFlags(t *testing.T) {
	testData := []struct {
		Name   string
		Input  uint32
		Expect EnhancedPacketBlockFlags
	}{
		{
			Name:  "pattern 1",
			Input: 0x80000025,
			Expect: EnhancedPacketBlockFlags{
				Bound:         Inbound,
				ReceptionType: Unicast,
				FCSLength:     1,
				LinkLayerDependentErrors: LinkLayerDependentErrors{
					SymbolError: true,
				},
			},
		},
		{
			Name:  "pattern 2",
			Input: 0x0000004a,
			Expect: EnhancedPacketBlockFlags{
				Bound:                    Outbound,
				ReceptionType:            Multicast,
				FCSLength:                2,
				LinkLayerDependentErrors: LinkLayerDependentErrors{},
			},
		},
		{
			Name:  "pattern 3",
			Input: 0x00000000,
			Expect: EnhancedPacketBlockFlags{
				Bound:                    BoundUnknown,
				ReceptionType:            ReceptionTypeNotSpecified,
				FCSLength:                0,
				LinkLayerDependentErrors: LinkLayerDependentErrors{},
			},
		},
	}

	for _, data := range testData {
		data := data // capture
		t.Run(data.Name, func(t *testing.T) {
			t.Parallel()

			actual := ParseEnhancedPacketBlockFlags(data.Input)
			if !reflect.DeepEqual(data.Expect, actual) {
				t.Fatalf("\nExpected: %+v\nActual:   %+v\n", data.Expect, actual)
			}
		})
	}
}

func TestLinkLayerDependentErrors(t *testing.T) {
	testData := []struct {
		Name      string
		FlagsWord uint16
		Flags     LinkLayerDependentErrors
	}{
		{
			Name:      "pattern 1",
			FlagsWord: 0x8000,
			Flags: LinkLayerDependentErrors{
				SymbolError: true,
			},
		},
		{
			Name:      "pattern 2",
			FlagsWord: 0x4000,
			Flags: LinkLayerDependentErrors{
				PreambleError: true,
			},
		},
		{
			Name:      "pattern 3",
			FlagsWord: 0x2000,
			Flags: LinkLayerDependentErrors{
				StartFrameDelimiterError: true,
			},
		},
		{
			Name:      "pattern 4",
			FlagsWord: 0x1000,
			Flags: LinkLayerDependentErrors{
				UnalignedFrameError: true,
			},
		},
		{
			Name:      "pattern 5",
			FlagsWord: 0x0800,
			Flags: LinkLayerDependentErrors{
				WrongInterFrameGapError: true,
			},
		},
		{
			Name:      "pattern 6",
			FlagsWord: 0x0400,
			Flags: LinkLayerDependentErrors{
				PacketTooShortError: true,
			},
		},
		{
			Name:      "pattern 7",
			FlagsWord: 0x0200,
			Flags: LinkLayerDependentErrors{
				PacketTooLongError: true,
			},
		},
		{
			Name:      "pattern 8",
			FlagsWord: 0x0100,
			Flags: LinkLayerDependentErrors{
				CRCError: true,
			},
		},
		{
			Name:      "pattern 9 - some errors",
			FlagsWord: 0xaa00,
			Flags: LinkLayerDependentErrors{
				SymbolError:              true,
				StartFrameDelimiterError: true,
				WrongInterFrameGapError:  true,
				PacketTooLongError:       true,
			},
		},
		{
			Name:      "pattern 10 - some errors",
			FlagsWord: 0x5500,
			Flags: LinkLayerDependentErrors{
				PreambleError:       true,
				UnalignedFrameError: true,
				PacketTooShortError: true,
				CRCError:            true,
			},
		},
	}

	for _, data := range testData {
		data := data // capture
		t.Run(data.Name, func(t *testing.T) {
			t.Parallel()

			flags := ParseLinkLayerDependentErrors(data.FlagsWord)
			if !reflect.DeepEqual(data.Flags, flags) {
				t.Fatalf("\nExpected: %+v\nActual:   %+v\n", data.Flags, flags)
			}

			flagsWord := flags.Encode()
			if data.FlagsWord != flagsWord {
				t.Fatalf("\nExpected: %+v\nActual:   %+v\n", data.FlagsWord, flagsWord)
			}
		})
	}

}
