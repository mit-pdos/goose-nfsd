package inode

import (
	"sync"

	"github.com/tchajed/goose/machine/disk"

	"github.com/mit-pdos/goose-nfsd/buf"
	"github.com/mit-pdos/goose-nfsd/fs"
	"github.com/mit-pdos/goose-nfsd/fstxn"
	"github.com/mit-pdos/goose-nfsd/util"
)

//
// Freeing of a file.  If file is large (i.e,., has indirect blocks),
// freeing is done in separate thread, using perhaps multiple
// transactions to ensure that the indirect blocks modified due to a
// free fit in the write-ahead log.
//

type ShrinkerSt struct {
	mu       *sync.Mutex
	condShut *sync.Cond
	nthread  uint32
	fsstate  *fstxn.FsState
}

var shrinkst *ShrinkerSt

func MkShrinkerSt(st *fstxn.FsState) *ShrinkerSt {
	mu := new(sync.Mutex)
	shrinkst = &ShrinkerSt{
		mu:       mu,
		condShut: sync.NewCond(mu),
		nthread:  0,
		fsstate:  st,
	}
	return shrinkst
}

func (shrinker *ShrinkerSt) Shutdown() {
	shrinker.mu.Lock()
	for shrinker.nthread > 0 {
		util.DPrintf(1, "ShutdownNfs: wait %d\n", shrinker.nthread)
		shrinker.condShut.Wait()
	}
	shrinker.mu.Unlock()
}

// 5: inode block, 2xbitmap block, indirect block, double indirect
func enoughLogSpace(op *fstxn.FsTxn) bool {
	return op.NumberDirty()+5 < op.LogSz()
}

func (ip *Inode) shrinkFits(op *fstxn.FsTxn) bool {
	nblk := util.RoundUp(ip.Size, disk.BlockSize) - ip.ShrinkSize
	return op.NumberDirty()+nblk < op.LogSz()
}

func (ip *Inode) IsShrinking() bool {
	cursz := util.RoundUp(ip.Size, disk.BlockSize)
	s := ip.ShrinkSize > cursz
	return s
}

func (ip *Inode) freeIndex(op *fstxn.FsTxn, index uint64) {
	op.FreeBlock(ip.blks[index])
	ip.blks[index] = 0
}

func (ip *Inode) Shrink(op *fstxn.FsTxn) {
	util.DPrintf(1, "Shrink: from %d to %d\n", ip.ShrinkSize,
		util.RoundUp(ip.Size, disk.BlockSize))
	for ip.IsShrinking() && enoughLogSpace(op) {
		ip.ShrinkSize--
		if ip.ShrinkSize < NDIRECT {
			ip.freeIndex(op, ip.ShrinkSize)
		} else {
			var off = ip.ShrinkSize - NDIRECT
			if off < NBLKBLK {
				freeroot := ip.indshrink(op, ip.blks[INDIRECT], 1, off)
				if freeroot != 0 {
					ip.freeIndex(op, INDIRECT)
				}
			} else {
				off = off - NBLKBLK
				freeroot := ip.indshrink(op, ip.blks[DINDIRECT], 2, off)
				if freeroot != 0 {
					ip.freeIndex(op, DINDIRECT)
				}
			}
		}
	}
	ip.WriteInode(op)
}

func shrinker(inum fs.Inum) {
	var more = true
	for more {
		op := fstxn.Begin(shrinkst.fsstate)
		ip := getInodeInumFree(op, inum)
		if ip == nil {
			panic("shrink")
		}
		ip.Shrink(op)
		more = ip.IsShrinking()
		ok := Commit(op, OneInode(ip))
		if !ok {
			panic("shrink")
		}
	}
	util.DPrintf(1, "Shrinker: done shrinking # %d\n", inum)
	shrinkst.mu.Lock()
	shrinkst.nthread = shrinkst.nthread - 1
	shrinkst.condShut.Signal()
	shrinkst.mu.Unlock()
}

// Frees indirect bn.  Assumes if bn is cleared, then all blocks > bn
// have been cleared
func (ip *Inode) indshrink(op *fstxn.FsTxn, root buf.Bnum, level uint64, bn uint64) buf.Bnum {
	if root == buf.NULLBNUM {
		return 0
	}
	if level == 0 {
		return root
	}
	divisor := pow(level - 1)
	off := (bn / divisor)
	ind := bn % divisor
	boff := off * 8
	b := op.ReadBlock(root)
	nxtroot := b.BnumGet(boff)
	op.AssertValidBlock(nxtroot)
	if nxtroot != 0 {
		freeroot := ip.indshrink(op, nxtroot, level-1, ind)
		if freeroot != 0 {
			b.BnumPut(boff, 0)
			op.FreeBlock(freeroot)
		}
	}
	if off == 0 && ind == 0 {
		return root
	} else {
		return buf.NULLBNUM
	}
}
