package report

import _ "embed"

var (
	//go:embed assets/chart.umd.min.js
	chartJSSource string
	//go:embed assets/d3.v7.min.js
	d3Source string
	//go:embed assets/venn.min.js
	vennSource string
	//go:embed assets/html2pdf.bundle.min.js
	html2pdfSource string
)

func chartJS() string {
	return chartJSSource
}

func d3JS() string {
	return d3Source
}

func vennJS() string {
	return vennSource
}

func html2pdfJS() string {
	return html2pdfSource
}
