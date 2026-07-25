package app

func parseLimitExceeded(totalNonEmpty, rejected int64, final bool) bool {
	if final {
		limit := totalNonEmpty / 1000
		if limit < 100 {
			limit = 100
		}
		return rejected > limit
	}
	if totalNonEmpty < 10000 {
		return rejected > 100
	}
	const scale int64 = 1000000
	minimumRejected := totalNonEmpty / scale * 50001
	remainder := totalNonEmpty % scale
	minimumRejected += (remainder*50001 + scale - 1) / scale
	return rejected >= minimumRejected
}
