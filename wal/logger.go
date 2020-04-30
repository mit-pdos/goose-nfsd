package wal

import (
	"github.com/mit-pdos/goose-nfsd/util"
)

// logAppend appends to the log, if it can find transactions to append.
//
// It grabs the new writes in memory and not on disk through l.nextDiskEnd; if
// there are any such writes, it commits them atomically.
//
// assumes caller holds memLock
//
// Returns true if it made progress (for liveness, not important for
// correctness).
func (l *Walog) logAppend() bool {
	// Wait until there is sufficient space on disk for the entire
	// in-memory log (i.e., the installer must catch up).
	for uint64(len(l.st.diskLog)+len(l.st.memLog)) > LOGSZ {
		l.condInstall.Wait()
	}
	// establishes uint64(len(l.memLog)) <= LOGSZ

	memlog := l.st.memLog
	newDiskEnd := l.st.nextDiskEnd
	diskEnd := l.st.diskEnd()
	newbufs := memlog[:newDiskEnd-diskEnd]
	if len(newbufs) == 0 {
		return false
	}
	l.memLock.Unlock()

	l.circ.Append(l.d, diskEnd, newbufs)

	l.memLock.Lock()
	l.st.diskLog = append(l.st.diskLog, newbufs...)
	l.st.memLog = l.st.memLog[newDiskEnd-diskEnd:]
	l.condLogger.Broadcast()
	l.condInstall.Broadcast()

	return true
}

// logger writes blocks from the in-memory log to the on-disk log
//
// Operates by continuously polling for in-memory transactions, driven by
// condLogger for scheduling
func (l *Walog) logger() {
	l.memLock.Lock()
	l.st.nthread += 1
	for !l.st.shutdown {
		progress := l.logAppend()
		if !progress {
			l.condLogger.Wait()
		}
	}
	util.DPrintf(1, "logger: shutdown\n")
	l.st.nthread -= 1
	l.condShut.Signal()
	l.memLock.Unlock()
}
