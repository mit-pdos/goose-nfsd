package goose_nfs

import (
	"path/filepath"

	"github.com/tchajed/goose/machine/disk"

	"github.com/mit-pdos/goose-nfsd/alloc"
	"github.com/mit-pdos/goose-nfsd/buf"
	"github.com/mit-pdos/goose-nfsd/cache"
	"github.com/mit-pdos/goose-nfsd/common"
	"github.com/mit-pdos/goose-nfsd/dir"
	"github.com/mit-pdos/goose-nfsd/fs"
	"github.com/mit-pdos/goose-nfsd/inode"
	"github.com/mit-pdos/goose-nfsd/txn"
	"github.com/mit-pdos/goose-nfsd/util"

	"math/rand"
	"os"
	"strconv"
)

const ICACHESZ uint64 = 100

type Nfs struct {
	Name       *string
	fsstate    *inode.FsState
	shrinkerst *inode.ShrinkerSt
}

func MkNfsMem(sz uint64) *Nfs {
	return MakeNfs(nil, sz)
}

func MkNfsName(name string, sz uint64) *Nfs {
	return MakeNfs(&name, sz)
}

func MkNfs(sz uint64) *Nfs {
	r := rand.Uint64()
	tmpdir := "/dev/shm"
	f, err := os.Stat(tmpdir)
	if !(err == nil && f.IsDir()) {
		tmpdir = os.TempDir()
	}
	n := filepath.Join(tmpdir, "goose"+strconv.FormatUint(r, 16)+".img")
	name := &n
	return MakeNfs(name, sz)
}

func MakeNfs(name *string, sz uint64) *Nfs {
	// run first so that disk is initialized before mkLog
	super := fs.MkFsSuper(sz, name)
	util.DPrintf(1, "Super: sz %d %v\n", sz, super)

	txn := txn.MkTxn(super) // runs recovery

	i := readRootInode(super)
	if i.Kind == 0 { // make a new file system?
		makeFs(super)
	}

	icache := cache.MkCache(ICACHESZ)
	balloc := alloc.MkAlloc(readBitmap(super, super.BitmapBlockStart(),
		super.NBlockBitmap))
	ialloc := alloc.MkAlloc(readBitmap(super, super.BitmapInodeStart(),
		super.NInodeBitmap))
	st := inode.MkFsState(super, txn, icache, balloc, ialloc)
	nfs := &Nfs{
		Name:       name,
		fsstate:    st,
		shrinkerst: inode.MkShrinkerSt(st),
	}
	if i.Kind == 0 {
		nfs.makeRootDir()
	}
	return nfs
}

func (nfs *Nfs) doShutdown(destroy bool) {
	util.DPrintf(1, "Shutdown %v\n", destroy)
	nfs.shrinkerst.Shutdown()
	nfs.fsstate.Txn.Shutdown()

	if destroy {
		util.DPrintf(1, "Destroy %v\n", *nfs.Name)
		os.Remove(*nfs.Name)
	}

	util.DPrintf(1, "Shutdown done\n")
}

func (nfs *Nfs) ShutdownNfsDestroy() {
	nfs.doShutdown(true)
}

func (nfs *Nfs) ShutdownNfs() {
	nfs.doShutdown(false)
}

func (nfs *Nfs) makeRootDir() {
	op := inode.Begin(nfs.fsstate)
	ip := inode.GetInodeInum(op, common.ROOTINUM)
	if ip == nil {
		panic("makeRootDir")
	}
	dir.MkRootDir(ip, op)
	ok := inode.Commit(op)
	if !ok {
		panic("makeRootDir")
	}
}

// Make an empty file system
func makeFs(super *fs.FsSuper) {
	util.DPrintf(1, "mkfs")

	root := inode.MkRootInode()
	util.DPrintf(1, "root %v\n", root)
	raddr := super.Inum2Addr(common.ROOTINUM)
	rootblk := root.Encode()
	rootbuf := buf.MkBuf(raddr, rootblk)
	rootbuf.WriteDirect(super.Disk)

	markAlloc(super, super.DataStart(), super.MaxBnum())
}

func markAlloc(super *fs.FsSuper, n common.Bnum, m common.Bnum) {
	util.DPrintf(1, "markAlloc: [0, %d) and [%d,%d)\n", n, m,
		super.NBlockBitmap*common.NBITBLOCK)
	if n >= common.Bnum(common.NBITBLOCK) ||
		m >= common.Bnum(common.NBITBLOCK*super.NBlockBitmap) ||
		m < n {
		panic("markAlloc: configuration makes no sense")
	}
	blk := make(disk.Block, disk.BlockSize)
	for bn := uint64(0); bn < uint64(n); bn++ {
		byte := bn / 8
		bit := bn % 8
		blk[byte] = blk[byte] | 1<<bit
	}
	super.Disk.Write(uint64(super.BitmapBlockStart()), blk)

	blk1 := blk
	blkno := m/common.Bnum(common.NBITBLOCK) + super.BitmapBlockStart()
	if blkno > super.BitmapBlockStart() {
		blk1 = make(disk.Block, disk.BlockSize)
	}
	for bn := uint64(m) % common.NBITBLOCK; bn < common.NBITBLOCK; bn++ {
		byte := bn / 8
		bit := bn % 8
		blk1[byte] = blk1[byte] | 1<<bit
	}
	super.Disk.Write(uint64(blkno), blk1)

	// mark inode 0 and 1 as allocated
	blk2 := make(disk.Block, disk.BlockSize)
	blk2[0] = blk2[0] | 1<<0
	blk2[0] = blk2[0] | 1<<1
	super.Disk.Write(uint64(super.BitmapInodeStart()), blk2)
}

func readRootInode(super *fs.FsSuper) *inode.Inode {
	addr := super.Inum2Addr(common.ROOTINUM)
	blk := super.Disk.Read(uint64(addr.Blkno))
	buf := buf.MkBufLoad(addr, blk)
	i := inode.Decode(buf, common.ROOTINUM)
	return i
}

func readBitmap(super *fs.FsSuper, start common.Bnum, len uint64) []byte {
	bitmap := make([]byte, 0)
	for i := uint64(0); i < len; i++ {
		blk := super.Disk.Read(uint64(start) + i)
		bitmap = append(bitmap, blk...)
	}
	return bitmap
}
