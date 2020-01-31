package buftxn

import (
	"github.com/tchajed/goose/machine/disk"

	"github.com/mit-pdos/goose-nfsd/buf"
	"github.com/mit-pdos/goose-nfsd/txn"
	"github.com/mit-pdos/goose-nfsd/util"
)

//
// Txn layer used by file system.  A transaction has locked addresses
// and buffers that it has read/written.  A transaction may hold more
// locks than buffers (e.g., it may have locked an inode, but read the
// inode from the file system's inode cache).
//

type BufTxn struct {
	txn   *txn.Txn
	bufs  *buf.BufMap // map of bufs read/written by trans
	id    txn.TransId
	addrs []buf.Addr // addresses locked by this transaction
}

func Begin(txn *txn.Txn) *BufTxn {
	trans := &BufTxn{
		txn:   txn,
		bufs:  buf.MkBufMap(),
		id:    txn.GetTransId(),
		addrs: make([]buf.Addr, 0),
	}
	util.DPrintf(1, "Begin: %v\n", trans.id)
	return trans
}

func (buftxn *BufTxn) IsLocked(addr buf.Addr) bool {
	var islocked = false
	for _, a := range buftxn.addrs {
		if addr.Eq(a) {
			islocked = true
			break
		}
	}
	return islocked
}

func (buftxn *BufTxn) ReadBufLocked(addr buf.Addr) *buf.Buf {
	// does this transaction already have addr locked?  (e.g.,
	// read the inode from the inode cache, after locking it)
	locked := buftxn.IsLocked(addr)
	if !locked {
		buftxn.Acquire(addr)
	}
	util.DPrintf(10, "ReadBufLocked: %d %v\n", buftxn.id, addr)
	return buftxn.ReadBuf(addr)
}

func (buftxn *BufTxn) ReadBuf(addr buf.Addr) *buf.Buf {
	b := buftxn.bufs.Lookup(addr)
	if b == nil {
		buf := buftxn.txn.Load(addr)
		buftxn.bufs.Insert(buf)
		return buftxn.bufs.Lookup(addr)
	}
	return b
}

// caller has disk object (e.g., from cache), so don't read disk
// object from disk if we don't have buf for it.
func (buftxn *BufTxn) OverWrite(addr buf.Addr, data []byte) {
	locked := buftxn.IsLocked(addr)
	if !locked {
		buftxn.Acquire(addr)
	}
	var b = buftxn.bufs.Lookup(addr)
	if b == nil {
		b = buf.MkBuf(addr, data)
		buftxn.bufs.Insert(b)
	} else {
		if uint64(len(data)*8) != b.Addr.Sz {
			panic("overwrite")
		}
		b.Blk = data
	}
	b.SetDirty()
}

func (buftxn *BufTxn) Acquire(addr buf.Addr) {
	buftxn.txn.Acquire(addr, buftxn.id)
	buftxn.addrs = append(buftxn.addrs, addr)
}

func (buftxn *BufTxn) deladdr(addr buf.Addr) {
	for i, a := range buftxn.addrs {
		if addr.Eq(a) {
			buftxn.addrs[i] = buftxn.addrs[len(buftxn.addrs)-1]
			buftxn.addrs = buftxn.addrs[:len(buftxn.addrs)-1]
		}
	}
}

func (buftxn *BufTxn) Release(addr buf.Addr) {
	buftxn.bufs.Del(addr)
	buftxn.deladdr(addr)
	buftxn.txn.Release(addr, buftxn.id)
}

func (buftxn *BufTxn) NDirty() uint64 {
	return buftxn.bufs.Ndirty()
}

func (buftxn *BufTxn) LogSz() uint64 {
	return buftxn.txn.LogSz()
}

func (buftxn *BufTxn) LogSzBytes() uint64 {
	return buftxn.txn.LogSz() * disk.BlockSize
}

// Sanity check for development
func (buftxn *BufTxn) check() {
	for _, b := range buftxn.bufs.DirtyBufs() {
		var found = false
		for _, a := range buftxn.addrs {
			if b.Addr.Eq(a) {
				found = true
				break
			}
		}
		if !found {
			util.DPrintf(0, "check: didn't find %v\n", b.Addr)
			panic("check")
		}
	}
}

// Commit dirty bufs of this transaction
func (buftxn *BufTxn) CommitWait(wait bool, abort bool) bool {
	// buftxn.check()
	util.DPrintf(1, "Commit %d w %v a %v\n", buftxn.id, wait, abort)
	return buftxn.txn.CommitWait(buftxn.addrs, buftxn.bufs.DirtyBufs(),
		wait, abort, buftxn.id)
}

func (buftxn *BufTxn) Flush() bool {
	return buftxn.txn.Flush(buftxn.addrs, buftxn.id)
}
