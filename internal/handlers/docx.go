package handlers

import (
	"archive/zip"
	"bytes"
	"strings"
)

// Minimal OOXML (.docx) builder — no external dependency. A .docx is a ZIP of
// a few XML parts; we emit just enough (content-types, package rels, and a
// single word/document.xml) for Word/LibreOffice to open a formatted report.
// UTF-8 throughout, so Turkish (ş/ğ/ı/İ) needs no special handling.

type docxBuilder struct {
	body strings.Builder
}

var docxXMLEscaper = strings.NewReplacer(
	"&", "&amp;",
	"<", "&lt;",
	">", "&gt;",
	`"`, "&quot;",
	"'", "&apos;",
)

// docxEscape makes scan-derived text safe for an XML 1.0 <w:t> node: it first
// drops characters XML 1.0 forbids outright (C0 controls except tab/LF/CR, DEL,
// the C1 range, and U+FFFE/U+FFFF) and repairs invalid UTF-8 — a raw HTTP body
// or TLS banner captured verbatim can contain a NUL/FF/ESC byte, which no
// numeric entity can encode and which would make word/document.xml unopenable —
// then escapes the five XML metacharacters. Without the strip pass, exporting a
// finding whose PoC carries a control byte produces a corrupt .docx.
func docxEscape(s string) string {
	return docxXMLEscaper.Replace(stripInvalidXML(s))
}

// stripInvalidXML removes runes not permitted by the XML 1.0 Char production.
func stripInvalidXML(s string) string {
	s = strings.ToValidUTF8(s, "")
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\t' || r == '\n' || r == '\r':
			return r
		case r < 0x20, r >= 0x7F && r <= 0x9F, r == 0xFFFE, r == 0xFFFF:
			return -1
		}
		return r
	}, s)
}

// run emits a single run with optional bold/mono/size(half-points) + color(hex).
func docxRun(text string, bold, mono bool, sizeHalfPt int, colorHex string) string {
	var rpr strings.Builder
	rpr.WriteString("<w:rPr>")
	if bold {
		rpr.WriteString("<w:b/>")
	}
	if mono {
		rpr.WriteString(`<w:rFonts w:ascii="Consolas" w:hAnsi="Consolas" w:cs="Consolas"/>`)
	}
	if colorHex != "" {
		rpr.WriteString(`<w:color w:val="` + colorHex + `"/>`)
	}
	if sizeHalfPt > 0 {
		rpr.WriteString(`<w:sz w:val="` + itoa(sizeHalfPt) + `"/>`)
	}
	rpr.WriteString("</w:rPr>")
	// Preserve leading/trailing whitespace and split explicit newlines into
	// <w:br/> so multi-line text keeps its shape.
	lines := strings.Split(text, "\n")
	var runs strings.Builder
	for i, ln := range lines {
		if i > 0 {
			runs.WriteString("<w:br/>")
		}
		runs.WriteString(`<w:t xml:space="preserve">` + docxEscape(ln) + `</w:t>`)
	}
	return "<w:r>" + rpr.String() + runs.String() + "</w:r>"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// heading adds a bold heading paragraph (sizePt in points).
func (d *docxBuilder) heading(text string, sizePt int, colorHex string) {
	d.body.WriteString("<w:p><w:pPr><w:spacing w:before=\"120\" w:after=\"80\"/></w:pPr>")
	d.body.WriteString(docxRun(text, true, false, sizePt*2, colorHex))
	d.body.WriteString("</w:p>")
}

// para adds a normal paragraph.
func (d *docxBuilder) para(text string) {
	d.body.WriteString("<w:p>")
	d.body.WriteString(docxRun(text, false, false, 0, ""))
	d.body.WriteString("</w:p>")
}

// mono adds a monospace paragraph (used for PoC request/response lines).
func (d *docxBuilder) mono(text string) {
	d.body.WriteString(`<w:p><w:pPr><w:shd w:val="clear" w:fill="F2F2F2"/></w:pPr>`)
	d.body.WriteString(docxRun(text, false, true, 16, ""))
	d.body.WriteString("</w:p>")
}

// pageBreak forces the next content onto a new page.
func (d *docxBuilder) pageBreak() {
	d.body.WriteString(`<w:p><w:r><w:br w:type="page"/></w:r></w:p>`)
}

// kvTable renders a two-column label/value table. Multi-line values keep their
// line breaks. Empty values render as "—".
func (d *docxBuilder) kvTable(rows [][2]string) {
	d.body.WriteString(`<w:tbl><w:tblPr><w:tblW w:w="5000" w:type="pct"/>` +
		`<w:tblBorders>` +
		`<w:top w:val="single" w:sz="4" w:color="CCCCCC"/>` +
		`<w:left w:val="single" w:sz="4" w:color="CCCCCC"/>` +
		`<w:bottom w:val="single" w:sz="4" w:color="CCCCCC"/>` +
		`<w:right w:val="single" w:sz="4" w:color="CCCCCC"/>` +
		`<w:insideH w:val="single" w:sz="4" w:color="CCCCCC"/>` +
		`<w:insideV w:val="single" w:sz="4" w:color="CCCCCC"/>` +
		`</w:tblBorders></w:tblPr>` +
		`<w:tblGrid><w:gridCol w:w="2600"/><w:gridCol w:w="6800"/></w:tblGrid>`)
	for _, r := range rows {
		label, value := r[0], r[1]
		if strings.TrimSpace(value) == "" {
			value = "—"
		}
		d.body.WriteString("<w:tr>")
		// label cell (shaded, bold)
		d.body.WriteString(`<w:tc><w:tcPr><w:tcW w:w="2600" w:type="dxa"/><w:shd w:val="clear" w:fill="F2F2F2"/></w:tcPr>`)
		d.body.WriteString("<w:p>" + docxRun(label, true, false, 0, "") + "</w:p>")
		d.body.WriteString("</w:tc>")
		// value cell — one paragraph per line
		d.body.WriteString(`<w:tc><w:tcPr><w:tcW w:w="6800" w:type="dxa"/></w:tcPr>`)
		for i, ln := range strings.Split(value, "\n") {
			_ = i
			d.body.WriteString("<w:p>" + docxRun(ln, false, false, 0, "") + "</w:p>")
		}
		d.body.WriteString("</w:tc>")
		d.body.WriteString("</w:tr>")
	}
	d.body.WriteString("</w:tbl>")
}

// bytes assembles the .docx zip and returns it.
func (d *docxBuilder) bytesOut() ([]byte, error) {
	const contentTypes = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>`
	const rootRels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>`
	const docRels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"></Relationships>`

	document := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>` +
		d.body.String() +
		`<w:sectPr><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1134" w:right="1134" w:bottom="1134" w:left="1134" w:header="708" w:footer="708" w:gutter="0"/></w:sectPr>` +
		`</w:body></w:document>`

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	files := []struct{ name, body string }{
		{"[Content_Types].xml", contentTypes},
		{"_rels/.rels", rootRels},
		{"word/_rels/document.xml.rels", docRels},
		{"word/document.xml", document},
	}
	for _, f := range files {
		w, err := zw.Create(f.name)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write([]byte(f.body)); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
