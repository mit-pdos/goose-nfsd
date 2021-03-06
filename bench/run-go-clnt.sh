#!/bin/sh

#
# Usage: ./run-go-clnt.sh  go run ./cmd/clnt-smallfile/main.go
#

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
# root of repo
cd $DIR/..

# taskset 0xc go run ./cmd/go-nfsd/ -disk /dev/shm/goose.img &
go run ./cmd/go-nfsd/ -disk /dev/shm/goose.img &
sleep 1
killall -0 go-nfsd # make sure server is running
# taskset 0x3 $1 /mnt/nfs
echo "$@"
"$@"
killall go-nfsd
