//go:build linux

package protect

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const anyGID uint32 = ^uint32(0)

func RequireMutationPlatform() error {
	return nil
}

func AcquireCoordinatorLock(config Config) (*FileLock, error) {
	path := filepath.Join(config.Nginx.ManagedDir, stateLockName)
	return acquireValidatedLockAnyGID(path, 0, 0o640, unix.O_RDONLY)
}

func AcquireApplyLock(config Config) (*FileLock, error) {
	path := filepath.Join(config.Nginx.ManagedDir, applyLockName)
	return acquireValidatedLock(path, 0, 0, 0o600, unix.O_RDWR)
}

func ProbeCoordinatorLock(config Config) error {
	path := filepath.Join(config.Nginx.ManagedDir, stateLockName)
	file, err := openValidatedLock(path, 0, anyGID, 0o640, unix.O_RDONLY)
	if err != nil {
		return err
	}
	defer file.Close()
	err = unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	switch {
	case errors.Is(err, unix.EWOULDBLOCK), errors.Is(err, unix.EAGAIN):
		return nil
	case err != nil:
		return err
	default:
		_ = unix.Flock(int(file.Fd()), unix.LOCK_UN)
		return errors.New("protect apply requires a coordinator-held state lock")
	}
}

func ValidateLiveSecurity(loaded LoadedConfig, executable string) (ServiceIdentity, error) {
	if os.Geteuid() == 0 {
		return ServiceIdentity{}, errors.New("watcher must run as a non-root service account")
	}
	if err := validateRootFile(loaded.Path, false); err != nil {
		return ServiceIdentity{}, err
	}
	for _, path := range []string{loaded.Config.Nginx.Binary, executable} {
		if err := validateRootExecutable(path); err != nil {
			return ServiceIdentity{}, err
		}
	}
	identity, err := validateServiceState(loaded.Config.Runtime.StateFile)
	if err != nil {
		return ServiceIdentity{}, err
	}
	groups, err := os.Getgroups()
	if err != nil {
		return ServiceIdentity{}, err
	}
	if uint32(os.Geteuid()) != identity.UID ||
		!containsProcessGroup(identity.GID, uint32(os.Getegid()), groups) {
		return ServiceIdentity{}, errors.New("watcher identity does not own the state directory")
	}
	if err := validateManagedSecurity(loaded.Config, identity); err != nil {
		return ServiceIdentity{}, err
	}
	return identity, nil
}

func ValidateApplySecurity(loaded LoadedConfig, executable string) (ServiceIdentity, error) {
	if os.Geteuid() != 0 {
		return ServiceIdentity{}, errors.New("protect apply must run as root")
	}
	if err := validateRootFile(loaded.Path, false); err != nil {
		return ServiceIdentity{}, err
	}
	for _, path := range []string{loaded.Config.Nginx.Binary, executable} {
		if err := validateRootExecutable(path); err != nil {
			return ServiceIdentity{}, err
		}
	}
	identity, err := validateServiceState(loaded.Config.Runtime.StateFile)
	if err != nil {
		return ServiceIdentity{}, err
	}
	if err := validateManagedSecurity(loaded.Config, identity); err != nil {
		return ServiceIdentity{}, err
	}
	return identity, nil
}

func ValidateSetupSecurity(loaded LoadedConfig, executable string) (ServiceIdentity, error) {
	if os.Geteuid() != 0 {
		return ServiceIdentity{}, errors.New("protect setup must run as root")
	}
	if err := validateRootFile(loaded.Path, false); err != nil {
		return ServiceIdentity{}, err
	}
	for _, path := range []string{loaded.Config.Nginx.Binary, executable} {
		if err := validateRootExecutable(path); err != nil {
			return ServiceIdentity{}, err
		}
	}
	return validateServiceState(loaded.Config.Runtime.StateFile)
}

func validateManagedSecurity(config Config, identity ServiceIdentity) error {
	if err := validateRootDirectory(config.Nginx.ManagedDir, identity.GID); err != nil {
		return err
	}
	for _, name := range []string{httpIncludeName, serverIncludeName, activeMapName} {
		if err := validateRootFile(filepath.Join(config.Nginx.ManagedDir, name), true); err != nil {
			return err
		}
	}
	stateLock := filepath.Join(config.Nginx.ManagedDir, stateLockName)
	file, err := openValidatedLock(stateLock, 0, identity.GID, 0o640, unix.O_RDONLY)
	if err != nil {
		return err
	}
	_ = file.Close()
	applyLock := filepath.Join(config.Nginx.ManagedDir, applyLockName)
	file, err = openValidatedLock(applyLock, 0, 0, 0o600, unix.O_RDWR)
	if err != nil {
		return err
	}
	return file.Close()
}

func ProvisionSetupLocks(config Config) (*FileLock, *FileLock, ServiceIdentity, error) {
	if os.Geteuid() != 0 {
		return nil, nil, ServiceIdentity{}, errors.New("protect setup must run as root")
	}
	identity, err := validateServiceState(config.Runtime.StateFile)
	if err != nil {
		return nil, nil, ServiceIdentity{}, err
	}
	if err := ensureRootDirectory(config.Nginx.ManagedDir, identity.GID); err != nil {
		return nil, nil, ServiceIdentity{}, err
	}
	statePath := filepath.Join(config.Nginx.ManagedDir, stateLockName)
	if err := createRootLock(statePath, identity.GID, 0o640); err != nil {
		return nil, nil, ServiceIdentity{}, err
	}
	applyPath := filepath.Join(config.Nginx.ManagedDir, applyLockName)
	if err := createRootLock(applyPath, 0, 0o600); err != nil {
		return nil, nil, ServiceIdentity{}, err
	}
	stateLock, err := acquireValidatedLock(statePath, 0, identity.GID, 0o640, unix.O_RDONLY)
	if err != nil {
		return nil, nil, ServiceIdentity{}, err
	}
	applyLock, err := acquireValidatedLock(applyPath, 0, 0, 0o600, unix.O_RDWR)
	if err != nil {
		_ = stateLock.Close()
		return nil, nil, ServiceIdentity{}, err
	}
	return stateLock, applyLock, identity, nil
}

func openNoSymlink(path string, flags int, mode uint32) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return nil, errors.New("path must be absolute and clean")
	}
	rootFD, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(rootFD)
	how := &unix.OpenHow{
		Flags:   uint64(flags | unix.O_CLOEXEC | unix.O_NOFOLLOW),
		Mode:    uint64(mode),
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS,
	}
	fd, err := unix.Openat2(rootFD, strings.TrimPrefix(path, "/"), how)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

func acquireValidatedLock(path string, uid, gid uint32, mode uint32, flags int) (*FileLock, error) {
	file, err := openValidatedLock(path, uid, gid, mode, flags)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, ErrLockHeld
		}
		return nil, err
	}
	return &FileLock{file: file}, nil
}

func acquireValidatedLockAnyGID(path string, uid, mode uint32, flags int) (*FileLock, error) {
	file, err := openValidatedLock(path, uid, anyGID, mode, flags)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, ErrLockHeld
		}
		return nil, err
	}
	return &FileLock{file: file}, nil
}

func openValidatedLock(path string, uid, gid, mode uint32, flags int) (*os.File, error) {
	file, err := openNoSymlink(path, flags, 0)
	if err != nil {
		return nil, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		_ = file.Close()
		return nil, err
	}
	validGID := gid == anyGID || stat.Gid == gid
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != uid || !validGID ||
		stat.Mode&0o777 != mode || stat.Nlink != 1 {
		_ = file.Close()
		return nil, errors.New("lock ownership, mode, type, or link count is unsafe")
	}
	return file, nil
}

func validateRootFile(path string, requireOneLink bool) error {
	file, err := openNoSymlink(path, unix.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != 0 || stat.Mode&0o022 != 0 ||
		requireOneLink && stat.Nlink != 1 {
		return errors.New("root-owned file is unsafe")
	}
	return nil
}

func validateRootExecutable(path string) error {
	file, err := openNoSymlink(path, unix.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != 0 || stat.Mode&0o022 != 0 || stat.Mode&0o111 == 0 {
		return errors.New("root-owned executable is unsafe")
	}
	return nil
}

func validateRootDirectory(path string, gid uint32) error {
	file, err := openNoSymlink(path, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return err
	}
	if !validManagedDirectoryStat(stat, gid) {
		return errors.New("root-owned directory is unsafe")
	}
	return nil
}

func validateServiceState(statePath string) (ServiceIdentity, error) {
	directoryPath := filepath.Dir(statePath)
	directory, err := openNoSymlink(directoryPath, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return ServiceIdentity{}, err
	}
	defer directory.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(int(directory.Fd()), &stat); err != nil {
		return ServiceIdentity{}, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid == 0 || stat.Mode&0o022 != 0 {
		return ServiceIdentity{}, errors.New("state directory must be service-owned and not writable by group or other")
	}
	identity := ServiceIdentity{UID: stat.Uid, GID: stat.Gid}
	state, err := openNoSymlink(statePath, unix.O_RDONLY, 0)
	if errors.Is(err, unix.ENOENT) {
		return identity, nil
	}
	if err != nil {
		return ServiceIdentity{}, err
	}
	defer state.Close()
	if err := unix.Fstat(int(state.Fd()), &stat); err != nil {
		return ServiceIdentity{}, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != identity.UID || stat.Gid != identity.GID ||
		stat.Mode&0o777 != 0o600 || stat.Nlink != 1 || stat.Size > maxStateBytes {
		return ServiceIdentity{}, errors.New("state file ownership, mode, type, link count, or size is unsafe")
	}
	return identity, nil
}

func ensureRootDirectory(path string, gid uint32) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return errors.New("managed directory path must be absolute and clean")
	}
	current, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(current) }()
	components := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for index, component := range components {
		created := false
		next, openErr := unix.Openat(
			current,
			component,
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
			0,
		)
		if errors.Is(openErr, unix.ENOENT) {
			if err := unix.Mkdirat(current, component, 0o755); err != nil {
				return err
			}
			if err := unix.Fsync(current); err != nil {
				return err
			}
			created = true
			next, openErr = unix.Openat(
				current,
				component,
				unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
				0,
			)
		}
		if openErr != nil {
			return openErr
		}
		var stat unix.Stat_t
		if err := unix.Fstat(next, &stat); err != nil {
			unix.Close(next)
			return err
		}
		if stat.Uid != 0 || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&0o022 != 0 {
			unix.Close(next)
			return errors.New("managed directory component is unsafe")
		}
		final := index == len(components)-1
		if final {
			if err := unix.Fchown(next, 0, int(gid)); err != nil {
				unix.Close(next)
				return err
			}
			if err := unix.Fchmod(next, 0o750); err != nil {
				unix.Close(next)
				return err
			}
			if err := unix.Fstat(next, &stat); err != nil || !validManagedDirectoryStat(stat, gid) {
				unix.Close(next)
				return errors.Join(err, errors.New("managed directory configuration is unsafe"))
			}
		} else {
			if created {
				if err := unix.Fchmod(next, 0o755); err != nil {
					unix.Close(next)
					return err
				}
				if err := unix.Fstat(next, &stat); err != nil {
					unix.Close(next)
					return err
				}
			}
			groupCanTraverse := stat.Gid == gid && stat.Mode&0o010 != 0
			if !groupCanTraverse && stat.Mode&0o001 == 0 {
				unix.Close(next)
				return errors.New("managed directory parent is not traversable by the service group")
			}
		}
		if err := unix.Fsync(next); err != nil {
			unix.Close(next)
			return err
		}
		unix.Close(current)
		current = next
	}
	return nil
}

func containsProcessGroup(gid, effectiveGID uint32, groups []int) bool {
	if gid == effectiveGID {
		return true
	}
	for _, group := range groups {
		if uint32(group) == gid {
			return true
		}
	}
	return false
}

func validManagedDirectoryStat(stat unix.Stat_t, gid uint32) bool {
	return stat.Mode&unix.S_IFMT == unix.S_IFDIR && stat.Uid == 0 && stat.Gid == gid &&
		stat.Mode&0o022 == 0 && stat.Mode&0o050 == 0o050
}

func createRootLock(path string, gid uint32, mode uint32) error {
	file, err := openNoSymlink(path, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL, mode)
	if errors.Is(err, unix.EEXIST) {
		return nil
	}
	if err != nil {
		return err
	}
	defer file.Close()
	if err := unix.Fchown(int(file.Fd()), 0, int(gid)); err != nil {
		return err
	}
	if err := unix.Fchmod(int(file.Fd()), mode); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	return nil
}
