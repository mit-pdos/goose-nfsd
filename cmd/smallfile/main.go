package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime/pprof"
	"strconv"
	"time"

	goose_nfs "github.com/mit-pdos/goose-nfsd"
	nfstypes "github.com/mit-pdos/goose-nfsd/nfstypes"
)

const BENCHDISKSZ uint64 = 100 * 1000

var cpuprofile = flag.String("cpuprofile", "", "write cpu profile to file")

func main() {
	flag.Parse()
	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}
	PSmallFile()
}

func SmallFile(clnt *goose_nfs.NfsClient, dirfh nfstypes.Nfs_fh3, name string, data []byte) {
	reply := clnt.LookupOp(dirfh, name)
	if reply.Status == nfstypes.NFS3_OK {
		panic("SmallFile")
	}
	clnt.CreateOp(dirfh, name)
	reply = clnt.LookupOp(dirfh, name)
	if reply.Status != nfstypes.NFS3_OK {
		panic("SmallFile")
	}
	attr := clnt.GetattrOp(reply.Resok.Object)
	if attr.Status != nfstypes.NFS3_OK {
		panic("SmallFile")
	}
	clnt.WriteOp(reply.Resok.Object, 0, data, nfstypes.FILE_SYNC)
	attr = clnt.GetattrOp(reply.Resok.Object)
	if attr.Status != nfstypes.NFS3_OK {
		panic("SmallFile")
	}
}

func mkdata(sz uint64) []byte {
	data := make([]byte, sz)
	for i := range data {
		data[i] = byte(i % 128)
	}
	return data
}

func PSmallFile() {
	const N = 1000000
	res := goose_nfs.Parallel(BENCHDISKSZ,
		func(clnt *goose_nfs.NfsClient, dirfh nfstypes.Nfs_fh3) int {
			data := mkdata(uint64(100))
			start := time.Now()
			i := 0
			for true {
				s := strconv.Itoa(i)
				SmallFile(clnt, dirfh, "x"+s, data)
				i++
				t := time.Now()
				elapsed := t.Sub(start)
				if elapsed.Microseconds() >= N {
					break
				}
			}
			return i
		})
	for i, v := range res {
		fmt.Printf("Smallfile: %d file in %d usec with %d threads\n",
			v, N, i+1)

	}
}
