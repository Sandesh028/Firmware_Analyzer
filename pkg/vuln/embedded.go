package vuln

import _ "embed"

// embeddedCuratedDatabase contains the curated vulnerability database bundled
// with releases. The file is generated via cmd/vulndbupdate.
//
//go:embed data/curated.json
var embeddedCuratedDatabase []byte
