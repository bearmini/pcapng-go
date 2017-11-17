package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/bearmini/pcapng-go/pcapng"
)

func main() {
	err := run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %+v\n", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) < 2 {
		return errors.New("no input file name is specified")
	}

	fname := os.Args[1]

	f, err := os.Open(fname)
	if err != nil {
		return err
	}
	defer f.Close()

	r := pcapng.NewReader(f)

	for {
		b, err := r.ReadNextBlock()
		if err != nil {
			return err
		}
		if b == nil {
			break
		}
		fmt.Printf("%s\n", b.String())
	}

	return nil
}
