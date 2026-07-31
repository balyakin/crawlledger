//go:build linux

package protect

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestLinuxOpenNoSymlinkRejectsAnySymlinkComponent(t *testing.T) {
	directory := t.TempDir()
	realDirectory := filepath.Join(directory, "real")
	linkDirectory := filepath.Join(directory, "link")
	if err := os.Mkdir(realDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(realDirectory, "file"), []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realDirectory, linkDirectory); err != nil {
		t.Fatal(err)
	}
	if _, err := openNoSymlink(filepath.Join(linkDirectory, "file"), unix.O_RDONLY, 0); err == nil {
		t.Fatal("symlink component accepted")
	}
}

func TestLinuxLockExclusionAndCrashRelease(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	first, err := acquireValidatedLock(path, uint32(os.Getuid()), uint32(os.Getgid()), 0o600, unix.O_RDWR)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := acquireValidatedLock(path, uint32(os.Getuid()), uint32(os.Getgid()), 0o600, unix.O_RDWR); !errors.Is(err, ErrLockHeld) {
		t.Fatalf("second lock returned %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := acquireValidatedLock(path, uint32(os.Getuid()), uint32(os.Getgid()), 0o600, unix.O_RDWR)
	if err != nil {
		t.Fatalf("released lock remained stale: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestLinuxLockRejectsModeAndHardLinks(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "lock")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := acquireValidatedLock(path, uint32(os.Getuid()), uint32(os.Getgid()), 0o600, unix.O_RDWR); err == nil {
		t.Fatal("wrong lock mode accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, filepath.Join(directory, "second-link")); err != nil {
		t.Fatal(err)
	}
	if _, err := acquireValidatedLock(path, uint32(os.Getuid()), uint32(os.Getgid()), 0o600, unix.O_RDWR); err == nil {
		t.Fatal("hard-linked lock accepted")
	}
}

func TestLinuxServiceGroupMayBeEffectiveOrSupplementary(t *testing.T) {
	if !containsProcessGroup(42, 42, nil) {
		t.Fatal("effective group was not recognized")
	}
	if !containsProcessGroup(42, 7, []int{7, 42}) {
		t.Fatal("supplementary service group was not recognized")
	}
	if containsProcessGroup(42, 7, []int{7, 8}) {
		t.Fatal("unrelated group was accepted")
	}
}

func TestLinuxManagedDirectoryPolicyRequiresServiceGroupAndTraversal(t *testing.T) {
	stat := unix.Stat_t{Mode: unix.S_IFDIR | 0o750, Uid: 0, Gid: 42}
	if !validManagedDirectoryStat(stat, 42) {
		t.Fatal("safe managed directory was rejected")
	}
	stat.Gid = 7
	if validManagedDirectoryStat(stat, 42) {
		t.Fatal("wrong managed-directory group was accepted")
	}
	stat.Gid = 42
	stat.Mode = unix.S_IFDIR | 0o700
	if validManagedDirectoryStat(stat, 42) {
		t.Fatal("managed directory without service-group traversal was accepted")
	}
}
