package goose_nfs

import (
	"github.com/tchajed/goose/machine/disk"
	"github.com/zeldovich/go-rpcgen/xdr"
	"log"
	"sort"
)

const ICACHESZ uint64 = 20
const BCACHESZ uint64 = 20

type Nfs struct {
	log *Log
	ic  *Cache
	fs  *FsSuper
	bc  *Cache
}

func MkNfs() *Nfs {
	fs := mkFsSuper() // run first so that disk is initialized before mkLog
	l := mkLog()
	if l == nil {
		panic("mkLog failed")
	}
	fs.initFs()
	ic := mkCache(ICACHESZ)
	bc := mkCache(BCACHESZ)
	go l.Logger()
	go Installer(bc, l)

	nfs := &Nfs{log: l, ic: ic, bc: bc, fs: fs}
	nfs.makeRootDir()
	return nfs
}

func (nfs *Nfs) makeRootDir() {
	txn := Begin(nfs.log, nfs.bc, nfs.fs, nfs.ic)
	ip := getInodeInum(txn, ROOTINUM)
	if ip == nil {
		panic("makeRootDir")
	}
	ip.mkRootDir(txn)
	txn.Commit([]*Inode{ip})
}

func (nfs *Nfs) ShutdownNfs() {
	nfs.log.Shutdown()
}

func errRet(txn *Txn, status *Nfsstat3, err Nfsstat3, inodes []*Inode) error {
	*status = err
	txn.Abort(inodes)
	return nil
}

func (nfs *Nfs) NullNFS(args *xdr.Void, reply *xdr.Void) error {
	log.Printf("NFS Null\n")
	return nil
}

func (nfs *Nfs) GetAttr(args *GETATTR3args, reply *GETATTR3res) error {
	log.Printf("NFS GetAttr %v\n", args)
	txn := Begin(nfs.log, nfs.bc, nfs.fs, nfs.ic)
	ip := getInode(txn, args.Object)
	if ip == nil {
		return errRet(txn, &reply.Status, NFS3ERR_STALE, nil)
	} else {
		reply.Status = NFS3_OK
		reply.Resok.Obj_attributes = ip.mkFattr()
		txn.Commit([]*Inode{ip})
	}
	return nil
}

func (nfs *Nfs) SetAttr(args *SETATTR3args, reply *SETATTR3res) error {
	log.Printf("NFS SetAttr %v\n", args)
	txn := Begin(nfs.log, nfs.bc, nfs.fs, nfs.ic)
	ip := getInode(txn, args.Object)
	if ip == nil {
		return errRet(txn, &reply.Status, NFS3ERR_STALE, nil)
	} else {
		if args.New_attributes.Size.Set_it {
			ok := ip.resize(txn,
				uint64(args.New_attributes.Size.Size))
			if !ok {
				return errRet(txn, &reply.Status, NFS3ERR_IO, []*Inode{ip})
			} else {
				reply.Status = NFS3_OK
				txn.Commit([]*Inode{ip})
			}
		} else {
			return errRet(txn, &reply.Status, NFS3ERR_NOTSUPP, []*Inode{ip})
		}
	}
	return nil
}

// Lock inodes in sorted order, but return the pointers in the same order as in inums
func lockInodes(txn *Txn, inums []Inum) []*Inode {
	log.Printf("lock inodes %v\n", inums)
	sorted := make([]Inum, len(inums))
	copy(sorted, inums)
	sort.Slice(sorted, func(i, j int) bool { return inums[i] < inums[j] })
	var inodes = make([]*Inode, len(inums))
	for _, inum := range sorted {
		ip := getInodeInum(txn, inum)
		if ip == nil {
			txn.Abort(inodes)
			return nil
		}
		// put in same position as in inums
		pos := func(inum uint64) int {
			for i, v := range inums {
				if v == inum {
					return i
				}
			}
			panic("func")
		}(inum)
		inodes[pos] = ip
	}
	return inodes
}

// First lookup inode up for child, then for parent, because parent
// inum > child inum and then revalidate that child is still in parent
// directory.
func (nfs *Nfs) LookupOrdered(txn *Txn, name Filename3, parent Fh, inum Inum) []*Inode {
	log.Printf("NFS LookupOrdered child %d parent %v\n", inum, parent)
	inodes := lockInodes(txn, []Inum{inum, parent.ino})
	if inodes == nil {
		return nil
	}
	dip := inodes[1]
	if dip.gen != parent.gen {
		txn.Abort(inodes)
		return nil
	}
	child, _ := dip.lookupName(txn, name)
	if child == NULLINUM || child != inum {
		txn.Abort(inodes)
		return nil
	}
	return inodes
}

// Lookup must lock child inode to find gen number, but child maybe a
// directory. We must lock directories in ascending inum order.
func (nfs *Nfs) Lookup(args *LOOKUP3args, reply *LOOKUP3res) error {
	var ip *Inode
	var inodes []*Inode
	var txn *Txn
	for ip == nil {
		txn = Begin(nfs.log, nfs.bc, nfs.fs, nfs.ic)
		log.Printf("NFS Lookup %v\n", args)
		dip := getInode(txn, args.What.Dir)
		if dip == nil {
			return errRet(txn, &reply.Status, NFS3ERR_STALE, nil)
		}
		inum, _ := dip.lookupName(txn, args.What.Name)
		if inum == NULLINUM {
			return errRet(txn, &reply.Status, NFS3ERR_NOENT, []*Inode{dip})
		}
		inodes = []*Inode{dip}
		if inum == dip.inum {
			ip = dip
		} else {
			if inum < dip.inum {
				// Abort. Try to lock inodes in order
				txn.Abort([]*Inode{dip})
				parent := args.What.Dir.makeFh()
				txn := Begin(nfs.log, nfs.bc, nfs.fs, nfs.ic)
				inodes = nfs.LookupOrdered(txn, args.What.Name,
					parent, inum)
				if inodes == nil {
					ip = nil
				} else {
					ip = inodes[0]
				}
			} else {
				ip = loadInode(txn, inum)
				if ip == nil {
					return errRet(txn, &reply.Status, NFS3ERR_IO,
						[]*Inode{dip})
				}
				ip.lock()
				inodes = []*Inode{ip, dip}
			}
		}
	}
	fh := Fh{ino: ip.inum, gen: ip.gen}
	reply.Status = NFS3_OK
	reply.Resok.Object = fh.makeFh3()
	txn.Commit(inodes)
	return nil
}

func (nfs *Nfs) Access(args *ACCESS3args, reply *ACCESS3res) error {
	log.Printf("NFS Access %v\n", args)
	reply.Status = NFS3_OK
	reply.Resok.Access = Uint32(ACCESS3_READ | ACCESS3_LOOKUP | ACCESS3_MODIFY | ACCESS3_EXTEND | ACCESS3_DELETE | ACCESS3_EXECUTE)
	return nil
}

func (nfs *Nfs) ReadLink(args *READLINK3args, reply *READLINK3res) error {
	log.Printf("NFS ReadLink %v\n", args)
	reply.Status = NFS3ERR_NOTSUPP
	return nil
}

func (nfs *Nfs) Read(args *READ3args, reply *READ3res) error {
	txn := Begin(nfs.log, nfs.bc, nfs.fs, nfs.ic)
	log.Printf("NFS Read %v %d %d\n", args.File, args.Offset, args.Count)
	ip := getInode(txn, args.File)
	if ip == nil {
		return errRet(txn, &reply.Status, NFS3ERR_STALE, nil)
	}
	if ip.kind != NF3REG {
		return errRet(txn, &reply.Status, NFS3ERR_INVAL, []*Inode{ip})
	}
	data, eof := ip.read(txn, uint64(args.Offset), uint64(args.Count))
	reply.Status = NFS3_OK
	reply.Resok.Count = Count3(len(data))
	reply.Resok.Data = data
	reply.Resok.Eof = eof
	txn.Commit([]*Inode{ip})
	return nil
}

// XXX Mtime
func (nfs *Nfs) Write(args *WRITE3args, reply *WRITE3res) error {
	txn := Begin(nfs.log, nfs.bc, nfs.fs, nfs.ic)
	log.Printf("NFS Write %v off %d cnt %d how %d\n", args.File, args.Offset,
		args.Count, args.Stable)
	ip := getInode(txn, args.File)
	fh := args.File.makeFh()
	if ip == nil {
		return errRet(txn, &reply.Status, NFS3ERR_STALE, nil)
	}
	if ip.kind != NF3REG {
		return errRet(txn, &reply.Status, NFS3ERR_INVAL, []*Inode{ip})
	}
	count, ok := ip.write(txn, uint64(args.Offset), uint64(args.Count), args.Data)
	if !ok {
		return errRet(txn, &reply.Status, NFS3ERR_NOSPC, []*Inode{ip})
	} else {
		reply.Status = NFS3_OK
		reply.Resok.Count = Count3(count)
		if args.Stable == FILE_SYNC {
			// RFC: "FILE_SYNC, the server must commit the
			// data written plus all file system metadata
			// to stable storage before returning results."
			txn.Commit([]*Inode{ip})
		} else if args.Stable == DATA_SYNC {
			// RFC: "DATA_SYNC, then the server must commit
			// all of the data to stable storage and
			// enough of the metadata to retrieve the data
			// before returning."
			txn.CommitData([]*Inode{ip}, fh)
		} else {
			// RFC:	"UNSTABLE, the server is free to commit
			// any part of the data and the metadata to
			// stable storage, including all or none,
			// before returning a reply to the
			// client. There is no guarantee whether or
			// when any uncommitted data will subsequently
			// be committed to stable storage. The only
			// guarantees made by the server are that it
			// will not destroy any data without changing
			// the value of verf and that it will not
			// commit the data and metadata at a level
			// less than that requested by the client."
			txn.CommitUnstable([]*Inode{ip}, fh)
		}
		reply.Resok.Committed = args.Stable
	}
	return nil
}

// XXX deal with how
func (nfs *Nfs) Create(args *CREATE3args, reply *CREATE3res) error {
	txn := Begin(nfs.log, nfs.bc, nfs.fs, nfs.ic)
	log.Printf("NFS Create %v\n", args)
	dip := getInode(txn, args.Where.Dir)
	if dip == nil {
		return errRet(txn, &reply.Status, NFS3ERR_STALE, nil)
	}
	inum1, _ := dip.lookupName(txn, args.Where.Name)
	if inum1 != NULLINUM {
		return errRet(txn, &reply.Status, NFS3ERR_EXIST, []*Inode{dip})
	}
	inum := nfs.fs.allocInode(txn, NF3REG)
	if inum == NULLINUM {
		return errRet(txn, &reply.Status, NFS3ERR_NOSPC, []*Inode{dip})
	}
	ok := dip.addName(txn, inum, args.Where.Name)
	if !ok {
		nfs.fs.freeInum(txn, inum)
		return errRet(txn, &reply.Status, NFS3ERR_IO, []*Inode{dip})
	}
	txn.Commit([]*Inode{dip})
	reply.Status = NFS3_OK
	return nil
}

func (nfs *Nfs) MakeDir(args *MKDIR3args, reply *MKDIR3res) error {
	txn := Begin(nfs.log, nfs.bc, nfs.fs, nfs.ic)
	log.Printf("NFS MakeDir %v\n", args)
	dip := getInode(txn, args.Where.Dir)
	if dip == nil {
		return errRet(txn, &reply.Status, NFS3ERR_STALE, nil)
	}
	inum1, _ := dip.lookupName(txn, args.Where.Name)
	if inum1 != NULLINUM {
		return errRet(txn, &reply.Status, NFS3ERR_EXIST, []*Inode{dip})
	}
	inum := nfs.fs.allocInode(txn, NF3DIR)
	if inum == NULLINUM {
		return errRet(txn, &reply.Status, NFS3ERR_NOSPC, []*Inode{dip})
	}
	ip := loadInode(txn, inum)
	if ip == nil {
		return errRet(txn, &reply.Status, NFS3ERR_IO, []*Inode{dip})
	}
	ip.lock()
	ok := ip.mkdir(txn, dip.inum)
	if !ok {
		ip.decLink(txn)
		return errRet(txn, &reply.Status, NFS3ERR_NOSPC, []*Inode{dip, ip})
	}
	ok1 := dip.addName(txn, inum, args.Where.Name)
	if !ok1 {
		ip.decLink(txn)
		return errRet(txn, &reply.Status, NFS3ERR_IO, []*Inode{dip, ip})
	}
	dip.nlink = dip.nlink + 1 // for ..
	ok = txn.fs.writeInode(txn, dip)
	if !ok {
		panic("mkdir")
	}
	txn.Commit([]*Inode{dip, ip})
	reply.Status = NFS3_OK
	return nil
}

func (nfs *Nfs) SymLink(args *SYMLINK3args, reply *SYMLINK3res) error {
	log.Printf("NFS MakeDir %v\n", args)
	reply.Status = NFS3ERR_NOTSUPP
	return nil
}

func (nfs *Nfs) MakeNod(args *MKNOD3args, reply *MKNOD3res) error {
	log.Printf("NFS MakeNod %v\n", args)
	reply.Status = NFS3ERR_NOTSUPP
	return nil
}

func (nfs *Nfs) Remove(args *REMOVE3args, reply *REMOVE3res) error {
	var ip *Inode
	var dip *Inode
	var inodes []*Inode
	var txn *Txn
	for ip == nil {
		txn = Begin(nfs.log, nfs.bc, nfs.fs, nfs.ic)
		log.Printf("NFS Remove %v\n", args)
		dip = getInode(txn, args.Object.Dir)
		if dip == nil {
			return errRet(txn, &reply.Status, NFS3ERR_STALE, nil)
		}
		if illegalName(args.Object.Name) {
			return errRet(txn, &reply.Status, NFS3ERR_INVAL, []*Inode{dip})
		}
		inum, _ := dip.lookupName(txn, args.Object.Name)
		if inum == NULLINUM {
			return errRet(txn, &reply.Status, NFS3ERR_NOENT, []*Inode{dip})
		}
		if inum < dip.inum {
			// Abort. Try to lock inodes in order
			txn.Abort([]*Inode{dip})
			txn := Begin(nfs.log, nfs.bc, nfs.fs, nfs.ic)
			parent := args.Object.Dir.makeFh()
			inodes = nfs.LookupOrdered(txn, args.Object.Name, parent, inum)
			ip = inodes[0]
			dip = inodes[1]
		} else {
			ip = loadInode(txn, inum)
			if ip == nil {
				return errRet(txn, &reply.Status, NFS3ERR_IO,
					[]*Inode{dip})
			}
			ip.lock()
			inodes = []*Inode{ip, dip}
		}
	}
	if ip.kind != NF3REG {
		return errRet(txn, &reply.Status, NFS3ERR_INVAL, inodes)
	}
	ok := dip.remName(txn, args.Object.Name)
	if !ok {
		return errRet(txn, &reply.Status, NFS3ERR_IO, inodes)
	}
	ip.decLink(txn)
	txn.Commit([]*Inode{ip, dip})
	reply.Status = NFS3_OK
	return nil
}

func (nfs *Nfs) RmDir(args *RMDIR3args, reply *RMDIR3res) error {
	log.Printf("NFS RmDir %v\n", args)
	reply.Status = NFS3ERR_NOTSUPP
	return nil
}

func validateRename(txn *Txn, inodes []*Inode, fromfh Fh, tofh Fh,
	fromn Filename3, ton Filename3) bool {
	var dipto *Inode
	var dipfrom *Inode
	var from *Inode
	var to *Inode
	if len(inodes) == 3 {
		dipfrom = inodes[0]
		dipto = inodes[0]
		from = inodes[1]
		to = inodes[2]
	} else {
		dipfrom = inodes[0]
		dipto = inodes[1]
		from = inodes[2]
		to = inodes[3]
	}
	if dipfrom.inum != fromfh.ino || dipfrom.gen != fromfh.gen ||
		dipto.inum != tofh.ino || dipto.gen != tofh.gen {
		log.Printf("revalidate ino failed\n")
		return false
	}
	frominum, _ := dipfrom.lookupName(txn, fromn)
	toinum, _ := dipto.lookupName(txn, ton)
	if from.inum != frominum || toinum != to.inum {
		log.Printf("revalidate inums failed\n")
		return false
	}
	return true
}

func (nfs *Nfs) Rename(args *RENAME3args, reply *RENAME3res) error {
	var dipto *Inode
	var dipfrom *Inode
	var txn *Txn
	var inodes []*Inode
	var frominum Inum
	var toinum Inum
	var success bool = false

	for !success {
		txn = Begin(nfs.log, nfs.bc, nfs.fs, nfs.ic)
		log.Printf("NFS Rename %v\n", args)

		toh := args.To.Dir.makeFh()
		fromh := args.From.Dir.makeFh()

		if illegalName(args.From.Name) {
			return errRet(txn, &reply.Status, NFS3ERR_INVAL, nil)
		}

		if args.From.Dir.equal(args.To.Dir) {
			dipfrom = getInode(txn, args.From.Dir)
			if dipfrom == nil {
				return errRet(txn, &reply.Status, NFS3ERR_STALE, nil)
			}
			dipto = dipfrom
			inodes = []*Inode{dipfrom}
		} else {
			inodes = lockInodes(txn, []Inum{fromh.ino, toh.ino})
			if inodes == nil {
				return errRet(txn, &reply.Status, NFS3ERR_STALE, inodes)
			}
			dipfrom = inodes[0]
			dipto = inodes[1]
		}

		log.Printf("from %v to %v\n", dipfrom, dipto)

		frominum, _ = dipfrom.lookupName(txn, args.From.Name)
		if frominum == NULLINUM {
			return errRet(txn, &reply.Status, NFS3ERR_NOENT, inodes)
		}

		toinum, _ = dipto.lookupName(txn, args.To.Name)

		log.Printf("frominum %d toinum %d\n", frominum, toinum)

		// rename to itself?
		if dipto == dipfrom && toinum == frominum {
			reply.Status = NFS3_OK
			txn.Commit(inodes)
			return nil
		}

		// does to exist?
		if toinum != NULLINUM {
			// need lock 4 inodes in order
			var to *Inode
			var from *Inode
			txn.Abort(inodes)
			txn = Begin(nfs.log, nfs.bc, nfs.fs, nfs.ic)
			if dipto != dipfrom {
				inodes = lockInodes(txn, []Inum{dipfrom.inum, dipto.inum,
					frominum, toinum})
				dipfrom = inodes[0]
				dipto = inodes[1]
				from = inodes[2]
				to = inodes[3]
			} else {
				inodes = lockInodes(txn, []Inum{dipfrom.inum, frominum, toinum})
				dipfrom = inodes[0]
				dipto = inodes[0]
				from = inodes[1]
				to = inodes[2]
			}
			log.Printf("inodes %v\n", inodes)
			if validateRename(txn, inodes, fromh, toh,
				args.From.Name, args.To.Name) {
				if to.kind != from.kind {
					return errRet(txn, &reply.Status, NFS3ERR_INVAL, inodes)
				}
				if to.kind == NF3DIR && !to.isDirEmpty(txn) {
					return errRet(txn, &reply.Status, NFS3ERR_NOTEMPTY, inodes)
				}
				ok := dipto.remName(txn, args.To.Name)
				if !ok {
					return errRet(txn, &reply.Status, NFS3ERR_IO, inodes)
				}
				to.decLink(txn)
				success = true
			} else { // retry
				txn.Abort(inodes)
			}
		} else {
			success = true
		}
	}
	ok := dipfrom.remName(txn, args.From.Name)
	if !ok {
		return errRet(txn, &reply.Status, NFS3ERR_IO, inodes)
	}
	ok1 := dipto.addName(txn, frominum, args.To.Name)
	if !ok1 {
		return errRet(txn, &reply.Status, NFS3ERR_IO, inodes)
	}
	txn.Commit(inodes)
	reply.Status = NFS3_OK
	return nil
}

func (nfs *Nfs) Link(args *LINK3args, reply *LINK3res) error {
	log.Printf("NFS Link %v\n", args)
	reply.Status = NFS3ERR_NOTSUPP
	return nil
}

func (nfs *Nfs) ReadDir(args *READDIR3args, reply *READDIR3res) error {
	log.Printf("NFS ReadDir %v\n", args)
	if args.Cookie != Cookie3(0) {
		reply.Status = NFS3ERR_NOTSUPP
		return nil
	}

	txn := Begin(nfs.log, nfs.bc, nfs.fs, nfs.ic)
	ip := getInode(txn, args.Dir)
	if ip == nil {
		return errRet(txn, &reply.Status, NFS3ERR_STALE, nil)
	}
	inodes := []*Inode{ip}
	if ip.kind != NF3DIR {
		return errRet(txn, &reply.Status, NFS3ERR_INVAL, inodes)
	}
	dirlist := ip.ls(txn, args.Count)
	log.Printf("dirlist %v\n", dirlist)
	// XXX check that entries fit in Count
	txn.Commit(inodes)
	reply.Status = NFS3_OK
	reply.Resok.Reply = dirlist
	return nil
}

func (nfs *Nfs) ReadDirPlus(args *READDIRPLUS3args, reply *READDIRPLUS3res) error {
	log.Printf("NFS ReadDirPlus %v\n", args)
	if args.Cookie != Cookie3(0) {
		reply.Status = NFS3ERR_NOTSUPP
		return nil
	}

	txn := Begin(nfs.log, nfs.bc, nfs.fs, nfs.ic)
	ip := getInode(txn, args.Dir)
	if ip == nil {
		return errRet(txn, &reply.Status, NFS3ERR_STALE, nil)
	}
	inodes := []*Inode{ip}
	if ip.kind != NF3DIR {
		return errRet(txn, &reply.Status, NFS3ERR_INVAL, inodes)
	}
	dirlist := ip.ls3(txn, args.Dircount)
	log.Printf("dirlist %v\n", dirlist)
	// XXX check that entries fit in Count
	txn.Commit(inodes)
	reply.Status = NFS3_OK
	reply.Resok.Reply = dirlist
	return nil
}

func (nfs *Nfs) FsStat(args *FSSTAT3args, reply *FSSTAT3res) error {
	log.Printf("NFS FsStat %v\n", args)
	reply.Status = NFS3ERR_NOTSUPP
	return nil
}

func (nfs *Nfs) FsInfo(args *FSINFO3args, reply *FSINFO3res) error {
	log.Printf("NFS FsInfo %v\n", args)
	reply.Status = NFS3_OK
	reply.Resok.Maxfilesize = Size3(NDIRECT * disk.BlockSize)
	return nil
}

func (nfs *Nfs) PathConf(args *PATHCONF3args, reply *PATHCONF3res) error {
	log.Printf("NFS PathConf %v\n", args)
	reply.Status = NFS3ERR_NOTSUPP
	return nil
}

// RFC: forces or flushes data to stable storage that was previously
// written with a WRITE procedure call with the stable field set to
// UNSTABLE.
func (nfs *Nfs) Commit(args *COMMIT3args, reply *COMMIT3res) error {
	log.Printf("NFS Commit %v\n", args)
	txn := Begin(nfs.log, nfs.bc, nfs.fs, nfs.ic)
	ip := getInode(txn, args.File)
	fh := args.File.makeFh()
	if ip == nil {
		return errRet(txn, &reply.Status, NFS3ERR_STALE, nil)
	}
	if ip.kind != NF3REG {
		return errRet(txn, &reply.Status, NFS3ERR_INVAL, []*Inode{ip})
	}
	ok := txn.CommitFh(fh, []*Inode{ip})
	if ok {
		reply.Status = NFS3_OK
	} else {
		return errRet(txn, &reply.Status, NFS3ERR_IO, []*Inode{ip})
	}
	return nil
}
