package version

import "runtime"

var (
	Version = "dev"
	Commit  = "unknown"
	Date    = "unknown"
)

type Info struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	BuiltAt string `json:"built_at"`
	Go      string `json:"go"`
}

func Current() Info {
	return Info{
		Version: Version,
		Commit:  Commit,
		BuiltAt: Date,
		Go:      runtime.Version(),
	}
}
