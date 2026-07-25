package app

type SanitizedPrivacy struct {
	ClientIP         string   `json:"client_ip"`
	QueryValues      string   `json:"query_values"`
	UserAgent        string   `json:"user_agent"`
	Referer          string   `json:"referer"`
	RawLinesRetained bool     `json:"raw_lines_retained"`
	Anonymous        bool     `json:"anonymous"`
	ResidualRisks    []string `json:"residual_risks"`
}

type SanitizedManifest struct {
	SchemaVersion  int              `json:"schema_version"`
	ToolVersion    string           `json:"tool_version"`
	CatalogVersion string           `json:"catalog_version"`
	KeyID          string           `json:"key_id"`
	CreatedAt      string           `json:"created_at"`
	Format         string           `json:"format"`
	Compression    string           `json:"compression"`
	SHA256         string           `json:"sha256"`
	Accepted       int64            `json:"accepted"`
	Rejected       int64            `json:"rejected"`
	Skipped        int64            `json:"skipped"`
	Privacy        SanitizedPrivacy `json:"privacy"`
	Warnings       []string         `json:"warnings"`
}
