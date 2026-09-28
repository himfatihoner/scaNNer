package handlers

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

// TestVulnPDFRenders confirms the PDF (with the new page-number SetFooterFunc)
// generates cleanly across pages. buildVulnPDF loads fonts from the repo-relative
// fontDir, so hop to the repo root for the duration.
func TestVulnPDFRenders(t *testing.T) {
	wd, _ := os.Getwd()
	defer os.Chdir(wd)
	os.Chdir("../..")
	if _, err := os.Stat(fontDir + "/DejaVuSans.ttf"); err != nil {
		t.Skip("bundled fonts not reachable from repo root; skipping PDF smoke test")
	}
	out, err := buildVulnPDF([]VulnReport{{ID: "SCN-ABC", Name: "Test finding"}}, "tr")
	if err != nil {
		t.Fatalf("buildVulnPDF: %v", err)
	}
	if len(out) < 500 || !bytes.HasPrefix(out, []byte("%PDF")) {
		t.Fatalf("output is not a valid PDF (len=%d)", len(out))
	}
}

// TestVulnDOCXPageNumberFooter verifies the exported .docx carries a page-number
// footer wired correctly into the OOXML package (part + content-type + rel +
// sectPr reference), so Word/LibreOffice render "Sayfa N / M".
func TestVulnDOCXPageNumberFooter(t *testing.T) {
	out, err := buildVulnDOCX([]VulnReport{{ID: "SCN-ABC", Name: "Test finding"}}, "tr")
	if err != nil {
		t.Fatalf("buildVulnDOCX: %v", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(out), int64(len(out)))
	if err != nil {
		t.Fatalf("open docx zip: %v", err)
	}
	parts := map[string]string{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open %s: %v", f.Name, err)
		}
		b, _ := io.ReadAll(rc)
		rc.Close()
		parts[f.Name] = string(b)
	}

	ftr, ok := parts["word/footer1.xml"]
	if !ok {
		t.Fatal("word/footer1.xml part missing")
	}
	for _, want := range []string{" PAGE ", " NUMPAGES ", "Sayfa"} {
		if !strings.Contains(ftr, want) {
			t.Errorf("footer1.xml missing %q", want)
		}
	}
	if doc := parts["word/document.xml"]; !strings.Contains(doc, `<w:footerReference w:type="default" r:id="rId1"/>`) {
		t.Error("document.xml missing footerReference")
	} else if !strings.Contains(doc, `xmlns:r=`) {
		t.Error("document.xml missing r: namespace for the footer rel id")
	}
	if !strings.Contains(parts["word/_rels/document.xml.rels"], `Target="footer1.xml"`) {
		t.Error("document.xml.rels missing the footer relationship")
	}
	if !strings.Contains(parts["[Content_Types].xml"], `PartName="/word/footer1.xml"`) {
		t.Error("[Content_Types].xml missing the footer override")
	}

	// EN variant renders and is a valid zip too.
	if outEN, err := buildVulnDOCX([]VulnReport{{ID: "SCN-XYZ"}}, "en"); err != nil {
		t.Fatalf("EN buildVulnDOCX: %v", err)
	} else if _, err := zip.NewReader(bytes.NewReader(outEN), int64(len(outEN))); err != nil {
		t.Fatalf("EN docx not a valid zip: %v", err)
	}
}

// TestDocxFooterXMLPlacement checks the field/text interleaving of the footer
// label without depending on a full report build.
func TestDocxFooterXMLPlacement(t *testing.T) {
	xml := docxFooterXML("Page {cur} of {tot}")
	iPage := strings.Index(xml, " PAGE ")
	iNum := strings.Index(xml, " NUMPAGES ")
	iOf := strings.Index(xml, "of")
	if iPage < 0 || iNum < 0 || iOf < 0 {
		t.Fatalf("missing field/text: %s", xml)
	}
	if !(iPage < iOf && iOf < iNum) {
		t.Errorf("expected PAGE < 'of' < NUMPAGES ordering, got PAGE=%d of=%d NUMPAGES=%d", iPage, iOf, iNum)
	}
}
