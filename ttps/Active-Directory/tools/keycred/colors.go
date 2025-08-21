package keycred

import (
	"strconv"
	"strings"
)

const (
	reset = 0
	bold  = 1
	faint = 2

	fgRed     = 31
	fgGreen   = 32
	fgBlue    = 34
	fgYellow  = 33
	fgMagenta = 35
)

func styleFunc(colors bool) func(...int) string {
	return func(attrs ...int) string {
		if !colors {
			return ""
		}

		if len(attrs) == 0 {
			// reset
			attrs = append(attrs, 0)
		}

		attrStrings := make([]string, 0, len(attrs))
		for _, attr := range attrs {
			attrStrings = append(attrStrings, strconv.Itoa(attr))
		}

		return "\x1b[" + strings.Join(attrStrings, ";") + "m"
	}
}
