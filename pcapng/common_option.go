package pcapng

import "github.com/pkg/errors"

func readCommonOptionComment(optionLength uint16, r *endiannessAwareReader, out *[]string) error {
	s, err := r.readString(uint(optionLength))
	if err != nil {
		return errors.Wrap(err, "unable to read comment")
	}
	if out == nil {
		a := make([]string, 0)
		out = &a
	}
	*out = append(*out, s)

	return nil
}
