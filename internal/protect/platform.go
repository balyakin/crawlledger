package protect

import (
	"errors"
	"os"
)

const stateLockName = "crawlledger-state.lock"
const applyLockName = "crawlledger-apply.lock"

var ErrUnsupportedPlatform = errors.New("Nginx mutation is supported only on Linux")
var ErrLockHeld = errors.New("protection lock is already held")

type FileLock struct {
	file *os.File
}

func (lock *FileLock) Close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	err := lock.file.Close()
	lock.file = nil
	return err
}

type ServiceIdentity struct {
	UID uint32
	GID uint32
}
