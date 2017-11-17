#!/bin/bash
d="$( cd "$( dirname "$0" )" || exit 1; cd ..; pwd )"
set -e
set -x

pushd "$d/pcapng/blocktype"
go generate
popd

pushd "$d/pcapng/linktype"
go generate
popd

pushd "$d/pcapng/examples/dump"
go build
popd
