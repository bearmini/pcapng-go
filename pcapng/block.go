package pcapng

import (
	"github.com/bearmini/pcapng-go/pcapng/blocktype"
)

type Block interface {
	GetType() blocktype.BlockType
	String() string
}
