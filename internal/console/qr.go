package console

import (
	"fmt"
	"html/template"
	"strings"

	"rsc.io/qr"
)

// qrSVG renders text as an inline SVG QR code (error correction M, the
// standard 4-module quiet zone). It is always dark on light — scanners
// expect that — whatever the page theme.
func qrSVG(text string) (template.HTML, error) {
	c, err := qr.Encode(text, qr.M)
	if err != nil {
		return "", err
	}
	const quiet = 4
	n := c.Size + 2*quiet
	var b strings.Builder
	fmt.Fprintf(&b, `<svg class="qr" viewBox="0 0 %d %d" role="img" shape-rendering="crispEdges">`, n, n)
	fmt.Fprintf(&b, `<rect width="%d" height="%d" fill="#fff"/><path fill="#000" d="`, n, n)
	for y := 0; y < c.Size; y++ {
		for x := 0; x < c.Size; x++ {
			if c.Black(x, y) {
				// One run per row segment keeps the path short.
				run := 1
				for x+run < c.Size && c.Black(x+run, y) {
					run++
				}
				fmt.Fprintf(&b, "M%d %dh%dv1h-%dz", x+quiet, y+quiet, run, run)
				x += run - 1
			}
		}
	}
	b.WriteString(`"/></svg>`)
	return template.HTML(b.String()), nil
}
