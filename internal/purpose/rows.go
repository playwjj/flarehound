package purpose

import "github.com/playwjj/flarehound/internal/cfapi"

// RowsOf turns a user-agent grouping (cfapi.Caps.UAPurposeDim) into rows.
func RowsOf(fs []cfapi.Face) []Row {
	out := make([]Row, 0, len(fs))
	for _, f := range fs {
		out = append(out, Row{UA: f.Name, ASN: f.ASN, Verified: f.Cat != "", Count: f.Count})
	}
	return out
}

// OptionsFor reads a grouping's dimension: what the rows carry.
func OptionsFor(dim string, hosting func(int) bool) Options {
	return Options{
		HasASN:  dim == cfapi.DimUAASNBot || dim == cfapi.DimUAASN,
		HasBot:  dim == cfapi.DimUAASNBot || dim == cfapi.DimUABot,
		Hosting: hosting,
	}
}

// RowLimit is how many UA groups a window's facet looks at: the bulk of
// the traffic; what is beyond it stays untagged (reports say how much
// the rows cover).
const RowLimit = 2000
