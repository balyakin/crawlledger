package report

import (
	"context"
	"embed"
	"html/template"
	"io"
	"math/bits"
	"os"
	"strconv"

	"github.com/balyakin/crawlledger/internal/atomicfile"
)

//go:embed templates/report.html.tmpl
var templateFiles embed.FS

func WriteHTML(ctx context.Context, root *os.Root, name string, model Model) ([]string, error) {
	value, err := template.New("report.html.tmpl").Funcs(template.FuncMap{
		"integer":  func(value int64) string { return strconv.FormatInt(value, 10) },
		"bytes":    formatBytes,
		"duration": formatDuration,
		"ratio":    formatRatio,
		"rub":      formatRUB,
	}).ParseFS(templateFiles, "templates/report.html.tmpl")
	if err != nil {
		return nil, err
	}
	return atomicfile.WriteNew(ctx, root, name, 0o600, func(writer io.Writer) error {
		return value.ExecuteTemplate(writer, "report.html.tmpl", model)
	})
}

func formatBytes(value int64) string {
	units := []string{"B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"}
	unit := int64(1)
	index := 0
	for index+1 < len(units) && value >= unit*1024 {
		unit *= 1024
		index++
	}
	if index == 0 {
		return strconv.FormatInt(value, 10) + " B"
	}
	return decimalOne(value, unit) + " " + units[index]
}

func formatDuration(value *int64) string {
	if value == nil {
		return "Not available"
	}
	switch {
	case *value < 1000:
		return strconv.FormatInt(*value, 10) + " µs"
	case *value < 1000000:
		return decimalOne(*value, 1000) + " ms"
	case *value < 60000000:
		return decimalOne(*value, 1000000) + " s"
	default:
		return decimalOne(*value, 60000000) + " min"
	}
}

func formatRatio(ppm int64) string {
	tenths := (ppm + 500) / 1000
	return strconv.FormatInt(tenths/10, 10) + "." + strconv.FormatInt(tenths%10, 10) + "%"
}

func formatRUB(kopecks *int64) string {
	if kopecks == nil {
		return "Not available"
	}
	return strconv.FormatInt(*kopecks/100, 10) + "." + twoDigits(*kopecks%100) + " RUB"
}

func decimalOne(value, unit int64) string {
	whole, remainder := value/unit, value%unit
	high, low := bits.Mul64(uint64(remainder), 10)
	tenth, _ := bits.Div64(high, low, uint64(unit))
	if tenth == 0 {
		return strconv.FormatInt(whole, 10)
	}
	return strconv.FormatInt(whole, 10) + "." + strconv.FormatUint(tenth, 10)
}

func twoDigits(value int64) string {
	if value < 10 {
		return "0" + strconv.FormatInt(value, 10)
	}
	return strconv.FormatInt(value, 10)
}
