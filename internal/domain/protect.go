package domain

type ProtectionHistory struct {
	InputFormat           string
	FirstEventUS          int64
	LastEventUS           int64
	RouteOverflowRequests int64
	Cells                 []ProtectionCell
}

type ProtectionCell struct {
	BucketMinuteUS     int64
	Route              string
	ActionablePrefix   *string
	RouteOverflow      bool
	Method             string
	Requests           int64
	UpstreamDurationUS int64
	UpstreamSamples    int64
}
