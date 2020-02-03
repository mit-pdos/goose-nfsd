package goose_nfs

import (
	"sort"

	"github.com/mit-pdos/goose-nfsd/common"
	"github.com/mit-pdos/goose-nfsd/dir"
	"github.com/mit-pdos/goose-nfsd/fh"
	"github.com/mit-pdos/goose-nfsd/inode"
	"github.com/mit-pdos/goose-nfsd/nfstypes"
	"github.com/mit-pdos/goose-nfsd/util"
)

// Lock inodes in sorted order, but return the pointers in the same order as in inums
// Caller must revalidate inodes.
func lockInodes(op *inode.FsTxn, inums []common.Inum) []*inode.Inode {
	util.DPrintf(1, "lock inodes %v\n", inums)
	sorted := make([]common.Inum, len(inums))
	copy(sorted, inums)
	sort.Slice(sorted, func(i, j int) bool { return inums[i] < inums[j] })
	var inodes = make([]*inode.Inode, len(inums))
	for _, inm := range sorted {
		ip := inode.GetInodeInum(op, inm)
		if ip == nil {
			inode.Abort(op)
			return nil
		}
		// put in same position as in inums
		pos := func(inm common.Inum) int {
			for i, v := range inums {
				if v == inm {
					return i
				}
			}
			panic("func")
		}(inm)
		inodes[pos] = ip
	}
	return inodes
}

func twoInums(inum1, inum2 common.Inum) []common.Inum {
	inums := make([]common.Inum, 2)
	inums[0] = inum1
	inums[1] = inum2
	return inums
}

// First lookup inode up for child, then for parent, because parent
// inum > child inum and then revalidate that child is still in parent
// directory.
func lookupOrdered(op *inode.FsTxn, name nfstypes.Filename3, parent fh.Fh, inm common.Inum) []*inode.Inode {
	util.DPrintf(5, "NFS lookupOrdered child %d parent %v\n", inm, parent)
	inodes := lockInodes(op, twoInums(inm, parent.Ino))
	if inodes == nil {
		return nil
	}
	dip := inodes[1]
	if dip.Gen != parent.Gen {
		inode.Abort(op)
		return nil
	}
	child, _ := dir.LookupName(dip, op, name)
	if child == common.NULLINUM || child != inm {
		inode.Abort(op)
		return nil
	}
	return inodes
}
