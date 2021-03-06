package dcache

import (
	"github.com/mit-pdos/go-journal/common"
)

type Dentry struct {
	Inum common.Inum
	Off  uint64
}

type Dcache struct {
	cache   map[string]Dentry
	Lastoff uint64
}

func MkDcache() *Dcache {
	return &Dcache{
		cache:   make(map[string]Dentry),
		Lastoff: uint64(0),
	}
}

func (dc *Dcache) Add(name string, inum common.Inum, off uint64) {
	dc.cache[name] = Dentry{Inum: inum, Off: off}
}

func (dc *Dcache) Lookup(name string) (Dentry, bool) {
	d, ok := dc.cache[name]
	return d, ok
}

func (dc *Dcache) Del(name string) bool {
	_, ok := dc.cache[name]
	if ok {
		delete(dc.cache, name)
	}
	return ok
}
