//go:build !linux

package protect

func RequireMutationPlatform() error {
	return ErrUnsupportedPlatform
}

func AcquireCoordinatorLock(Config) (*FileLock, error) {
	return nil, ErrUnsupportedPlatform
}

func AcquireApplyLock(Config) (*FileLock, error) {
	return nil, ErrUnsupportedPlatform
}

func ProbeCoordinatorLock(Config) error {
	return ErrUnsupportedPlatform
}

func ValidateLiveSecurity(LoadedConfig, string) (ServiceIdentity, error) {
	return ServiceIdentity{}, ErrUnsupportedPlatform
}

func ValidateApplySecurity(LoadedConfig, string) (ServiceIdentity, error) {
	return ServiceIdentity{}, ErrUnsupportedPlatform
}

func ValidateSetupSecurity(LoadedConfig, string) (ServiceIdentity, error) {
	return ServiceIdentity{}, ErrUnsupportedPlatform
}

func ProvisionSetupLocks(Config) (*FileLock, *FileLock, ServiceIdentity, error) {
	return nil, nil, ServiceIdentity{}, ErrUnsupportedPlatform
}
