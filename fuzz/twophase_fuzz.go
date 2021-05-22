package fuzz

import (
	"bytes"
	"errors"
	"encoding/binary"
	"fmt"

	"github.com/tchajed/goose/machine/disk"

	"github.com/mit-pdos/goose-nfsd/addr"
	"github.com/mit-pdos/goose-nfsd/twophase"
)

var DEBUG bool = false

type MockDisk struct {
	seenAddrs []uint64
	logszspec map[uint64]uint64
	data map[uint64][]byte
}

func NewMockDisk() *MockDisk {
	return &MockDisk{
		seenAddrs: make([]uint64, 0),
		logszspec: make(map[uint64]uint64),
		data: make(map[uint64][]byte),
	}
}

func (md *MockDisk) Clone() *MockDisk {
	nmd := NewMockDisk()
	nmd.seenAddrs = md.seenAddrs
	for k, v := range md.logszspec {
		nmd.logszspec[k] = v
	}
	for k, v := range md.data {
		nmd.data[k] = v
	}
	return nmd
}

func (md *MockDisk) Write(tp *twophase.TwoPhase, a uint64, logsz uint64, data []byte) error {
	sz := uint64(1 << logsz)
	if sz != 1 && uint64(len(data)) * 8 != sz {
		panic("wrong data len")
	}
	blkno := a / (disk.BlockSize*8)
	off := a % (disk.BlockSize*8)
	logszspec, inspec := md.logszspec[blkno]
	if inspec && logszspec != logsz {
		panic("size doesn't match spec")
	}
	if a % sz != 0 {
		panic("address not aligned")
	}
	_, inseen := md.data[a]
	if !inseen {
		md.seenAddrs = append(md.seenAddrs, a)
	}
	md.logszspec[blkno] = logsz
	md.data[a] = data
	tp.OverWrite(addr.MkAddr(blkno + 513, off), sz, data)
	return nil
}

func (md *MockDisk) Read(tp *twophase.TwoPhase, a uint64) error {
	blkno := a / (disk.BlockSize*8)
	off := a % (disk.BlockSize*8)
	expected, indata := md.data[a]
	logsz, inspec := md.logszspec[blkno]
	if !indata || !inspec {
		return errors.New("address not in spec")
	}
	sz := uint64(1) << logsz
	data := tp.ReadBuf(addr.MkAddr(blkno + 513, off), sz)
	if sz == 1 {
		bitoff := off % 8
		if ((data[0] >> bitoff) & 1) != ((expected[0] >> bitoff) & 1) {
			panic("disk inconsistency")
		}
	} else {
		if !bytes.Equal(data, expected) {
			panic("disk inconsistency")
		}
	}
	return nil
}

func Fuzz(data []byte) int {
	dataptr := 0
	getByte := func() byte {
		if dataptr >= len(data) {
			return 0
		}
		res := data[dataptr]
		dataptr ++
		return res
	}
	getBytes := func(n uint64) []byte {
		res := make([]byte, n)
		resptr := uint64(0)
		for dataptr < len(data) && resptr < n {
			res[resptr] = data[dataptr]
			dataptr++
			resptr++
		}
		return res
	}
	getUint64 := func() uint64 {
		return binary.BigEndian.Uint64(getBytes(8))
	}

	DISK_SIZE := uint64(4)
	md := NewMockDisk()
	d := disk.NewMemDisk(DISK_SIZE + 513)
	tpPre := twophase.Init(d)
	tp := twophase.Begin(tpPre)

	mdtxn := md.Clone()
	numCommits := 0
	numReads := 0
	for dataptr < len(data) {
		cmd := getByte() % 3
		switch cmd {
		case 0:
			// commit
			if DEBUG {
				fmt.Printf("c\n")
			}
			success := tp.Commit()
			tp = twophase.Begin(tpPre)
			if success {
				md = mdtxn
				mdtxn = md.Clone()
			} else {
				mdtxn = md
			}
			numCommits++
		case 1:
			// read
			if len(mdtxn.seenAddrs) == 0 {
				continue
			}
			a := mdtxn.seenAddrs[getUint64() % uint64(len(mdtxn.seenAddrs))]
			if DEBUG {
				fmt.Printf("r %d\n", a)
			}
			err := mdtxn.Read(tp, a)
			if err != nil {
				return 0
			}
			numReads++
		case 2:
			// write
			a := getUint64() % (DISK_SIZE * disk.BlockSize * 8)
			logsz := getUint64() % 11
			if logsz > 0 {
				logsz += 2
			}
			logszspec, inspec := mdtxn.logszspec[a / (disk.BlockSize*8)]
			if inspec {
				logsz = logszspec
			}
			a = (a >> logsz) << logsz
			if a + (uint64(1) << logsz) > DISK_SIZE * disk.BlockSize * 8 {
				panic("should not happen")
			}
			datasz := uint64(1) << logsz
			if logsz > 0 {
				datasz >>= 3
			}
			data := getBytes(datasz)
			if DEBUG {
				fmt.Printf("w %d %d\n", a, (uint64(1) << logsz))
			}
			err := mdtxn.Write(tp, a, logsz, data)
			if err != nil {
				return 0
			}
		}
	}
	tp.Commit()
	if numCommits == 0 || numReads == 0 {
		return 0
	}
	return 1
}
