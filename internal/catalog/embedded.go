package catalog

import _ "embed"

//go:embed data/crawlers-v1.json
var embeddedCatalog []byte

func LoadEmbedded() (*Catalog, error) { return load(embeddedCatalog) }
