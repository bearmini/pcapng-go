package pcapng

import (
	"github.com/bearmini/pcapng-go/pcapng/optioncode"
	"github.com/pkg/errors"
)

type CustomOption struct {
	OptionCode   optioncode.OptionCode
	OptionLength uint16
	PEN          uint32
	Data         []byte
}

func readCustomOption(optionCode, optionLength uint16, r *endiannessAwareReader, out *[]CustomOption) error {
	pen, err := r.readUint32()
	if err != nil {
		return errors.Wrap(err, "unable to read PEN in a custom option")
	}
	data, err := r.readBytes(uint(optionLength))
	if err != nil {
		return errors.Wrap(err, "unable to read data in a custom option")
	}

	if out == nil {
		a := make([]CustomOption, 0)
		out = &a
	}
	*out = append(*out, CustomOption{
		OptionCode:   optioncode.OptionCode(optionCode),
		OptionLength: optionLength,
		PEN:          pen,
		Data:         data,
	})

	return nil
}
