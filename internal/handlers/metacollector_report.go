package handlers

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-pdf/fpdf"

	"scanner/internal/modules/metacollector"
)

// Branded PDF/CSV/JSON report for the Google Metadata Collector module — an
// fpdf port of meta-collector/metacollector/pdfreport.py (ReportLab+matplotlib).
// Themes: the 6 named presets (exact hex from the reference) plus a free hex
// "custom" colour, since we own the renderer. Bilingual (tr/en). Charts are
// drawn natively with fpdf primitives (no external charting dependency).

// metaReportOptions captures the export-form customization.
type metaReportOptions struct {
	Theme     string // preset name (red/blue/green/purple/teal/slate) or "custom"
	Color     string // #RRGGBB when Theme == "custom"
	Logo      []byte
	Title     string
	TargetOrg string
	Appendix  string // "full" | "none"
	Lang      string // "tr" | "en"
}

// ---- theme ----

type metaTheme struct {
	primary [3]int
	dark    [3]int
	soft    [3]int
	bar2    [3]int
	palette [][3]int
}

// Neutral palette — fixed across all themes (pdfreport.py constants).
var (
	mcSLATE  = [3]int{0x3F, 0x46, 0x51}
	mcINK    = [3]int{0x1F, 0x29, 0x37}
	mcMUTED  = [3]int{0x6B, 0x72, 0x80}
	mcZEBRA  = [3]int{0xF4, 0xF4, 0xF5}
	mcBORDER = [3]int{0xE5, 0xE7, 0xEB}
	mcKVBG   = [3]int{0xF3, 0xF4, 0xF6}
	mcWHITE  = [3]int{0xFF, 0xFF, 0xFF}
	mcCGRID  = [3]int{0xE5, 0xE7, 0xEB}
	mcCVAL   = [3]int{0x4B, 0x55, 0x63}
)

func hexRGB(h string) [3]int {
	h = strings.TrimPrefix(strings.TrimSpace(h), "#")
	if len(h) != 6 {
		return [3]int{0, 0, 0}
	}
	r, _ := strconv.ParseInt(h[0:2], 16, 0)
	g, _ := strconv.ParseInt(h[2:4], 16, 0)
	b, _ := strconv.ParseInt(h[4:6], 16, 0)
	return [3]int{int(r), int(g), int(b)}
}

func hexSlice(hs ...string) [][3]int {
	out := make([][3]int, 0, len(hs))
	for _, h := range hs {
		out = append(out, hexRGB(h))
	}
	return out
}

// metaThemePresets — the 6 named themes, exact hex from pdfreport.py:124-158.
var metaThemePresets = map[string]metaTheme{
	"red": {hexRGB("#A23B3B"), hexRGB("#7A2E2E"), hexRGB("#C97B7B"), hexRGB("#B65C5C"),
		hexSlice("#A23B3B", "#C97B7B", "#7A2E2E", "#9AA0A6", "#D8A0A0", "#5B6470", "#B65C5C", "#C9CCD1", "#8C3A3A", "#6B7280")},
	"blue": {hexRGB("#3B5E8C"), hexRGB("#2E4767"), hexRGB("#7B9AC9"), hexRGB("#5C7DB6"),
		hexSlice("#3B5E8C", "#7B9AC9", "#2E4767", "#9AA0A6", "#A0BCD8", "#5B6470", "#5C7DB6", "#C9CCD1", "#3A5A8C", "#6B7280")},
	"green": {hexRGB("#3B7A57"), hexRGB("#2E5C41"), hexRGB("#7BC99A"), hexRGB("#5CB67D"),
		hexSlice("#3B7A57", "#7BC99A", "#2E5C41", "#9AA0A6", "#A0D8B6", "#5B6470", "#5CB67D", "#C9CCD1", "#3A6E50", "#6B7280")},
	"purple": {hexRGB("#6B4A8C"), hexRGB("#503867"), hexRGB("#A98BC9"), hexRGB("#8C6CB6"),
		hexSlice("#6B4A8C", "#A98BC9", "#503867", "#9AA0A6", "#C2A8D8", "#5B6470", "#8C6CB6", "#C9CCD1", "#5E3F7E", "#6B7280")},
	"teal": {hexRGB("#2E7D7B"), hexRGB("#235E5C"), hexRGB("#7BC9C7"), hexRGB("#5CB6B4"),
		hexSlice("#2E7D7B", "#7BC9C7", "#235E5C", "#9AA0A6", "#A0D8D6", "#5B6470", "#5CB6B4", "#C9CCD1", "#2C706E", "#6B7280")},
	"slate": {hexRGB("#3F4651"), hexRGB("#2B313A"), hexRGB("#8A93A1"), hexRGB("#5E6675"),
		hexSlice("#3F4651", "#8A93A1", "#2B313A", "#9AA0A6", "#AAB2BE", "#5B6470", "#5E6675", "#C9CCD1", "#363C45", "#6B7280")},
}

func scaleColor(c [3]int, f float64) [3]int {
	clamp := func(v float64) int {
		if v < 0 {
			return 0
		}
		if v > 255 {
			return 255
		}
		return int(v)
	}
	return [3]int{clamp(float64(c[0]) * f), clamp(float64(c[1]) * f), clamp(float64(c[2]) * f)}
}

func mixWhite(c [3]int, t float64) [3]int {
	m := func(v int) int { return int(float64(v)*(1-t) + 255*t) }
	return [3]int{m(c[0]), m(c[1]), m(c[2])}
}

// customTheme derives a full theme from a single primary hex (the free colour).
func customTheme(hex string) metaTheme {
	p := hexRGB(hex)
	dark := scaleColor(p, 0.72)
	soft := mixWhite(p, 0.55)
	bar2 := scaleColor(p, 0.9)
	return metaTheme{
		primary: p, dark: dark, soft: soft, bar2: bar2,
		palette: [][3]int{p, soft, dark, hexRGB("#9AA0A6"), mixWhite(p, 0.75), hexRGB("#5B6470"),
			bar2, hexRGB("#C9CCD1"), scaleColor(p, 0.82), hexRGB("#6B7280")},
	}
}

func resolveMetaTheme(o metaReportOptions) metaTheme {
	if o.Theme == "custom" && len(strings.TrimPrefix(o.Color, "#")) == 6 {
		return customTheme(o.Color)
	}
	if t, ok := metaThemePresets[strings.ToLower(o.Theme)]; ok {
		return t
	}
	return metaThemePresets["red"]
}

// ---- labels (tr/en) ----

type metaLabels struct {
	coverTitle, contents                                             string
	hExec, hCharts, hScope, hTables, hCorr, hAppendix, hRec, hGloss  string
	mOrg, mDomain, mDocs, mProvider, mDate                           string
	kDoc, kUser, kEmail, kSoftware, kLeak                            string
	colDocs, colType, colValue                                       string
	tUsers, tSoftware, tEmails, tCompany, tPathsServers              string
	capPie, capDonut, capUsers, capSoftware, capEmails, capTimeline  string
	corrCaption, corrUser, corrSoftware, corrPathOS                  string
	appDocs, appNoMeta, appDisabled                                  string
	scopeProvider, scopeMethod, scopeMethodText, scopeTypes          string
	scopeSubdomains, scopeDocStatus                                  string
	recIntro, recHowTo, legalNote                                    string
	execTemplate                                                     string
	recBullets                                                       []string
	cleanupSteps                                                     [][2]string
	glossary                                                         [][2]string
	pageOf                                                           string
}

func metaLabelsFor(lang string) metaLabels {
	if strings.EqualFold(lang, "en") {
		return metaLabelsEN
	}
	return metaLabelsTR
}

var metaLabelsTR = metaLabels{
	coverTitle: "Metadata İstihbarat Raporu", contents: "İçindekiler",
	hExec: "Yönetici Özeti", hCharts: "Bulgu Grafikleri", hScope: "Tarama Kapsamı ve Metodolojisi",
	hTables: "Özet Tablolar", hCorr: "Kullanıcı – Yazılım / Yol Korelasyonu",
	hAppendix: "Bulgular — Dosya Bazlı Detay", hRec: "Riskler ve Öneriler", hGloss: "Terimler Sözlüğü",
	mOrg: "Hedef Kurum", mDomain: "Hedef alan adı", mDocs: "Doküman sayısı", mProvider: "Arama sağlayıcı", mDate: "Tarama tarihi",
	kDoc: "Doküman", kUser: "Kullanıcı", kEmail: "E-posta", kSoftware: "Yazılım", kLeak: "İç yol/sunucu",
	colDocs: "# doküman", colType: "Tür", colValue: "Değer",
	tUsers: "Kullanıcılar / Yazarlar", tSoftware: "Yazılım Envanteri", tEmails: "E-posta Adresleri",
	tCompany: "Kurum Bilgisi", tPathsServers: "İç Yollar ve Sunucular (Hassas)",
	capPie: "Hangi türlerde metadata sızdırıldı", capDonut: "Dosya tiplerine göre doküman dağılımı",
	capUsers: "En çok geçen kullanıcılar", capSoftware: "En sık yazılımlar", capEmails: "En sık e-posta adresleri",
	capTimeline: "Zaman çizelgesi (oluşturma/değiştirme tarihleri)",
	corrCaption:  "Aynı dokümanlarda görülen kullanıcı ↔ yazılım/işletim sistemi/yol ilişkisi.",
	corrUser:     "Kullanıcı", corrSoftware: "Yazılım", corrPathOS: "Yol / OS",
	appDocs: "%d doküman", appNoMeta: "(metadata bulunamadı)", appDisabled: "(Detay eki devre dışı.)",
	scopeProvider: "Sağlayıcı", scopeMethod: "Yöntem",
	scopeMethodText: "Google dork: site:<alan adı> (filetype:...) → indirme → exiftool + gövde metni",
	scopeTypes: "Aranan tipler", scopeSubdomains: "Bulunan alt alan adı", scopeDocStatus: "Doküman durumu",
	recIntro: "Yayımlanan dokümanların metadata'sı; kullanıcı adları, iç ağ yolları, yazılım envanteri ve e-posta adresleri gibi bilgileri açığa çıkararak hedef hakkında pasif istihbarat sağlar. Alınması gereken önlemler:",
	recHowTo: "Metadata Nasıl Temizlenir?",
	legalNote: "Yasal not: Bu rapor yalnızca yetkili güvenlik testi / OSINT amaçlıdır. İçerdiği kişisel veriler KVKK kapsamında işlenmeli ve süresi dolunca imha edilmelidir.",
	execTemplate: "Bu rapor, hedef üzerinde taranan %d dokümanın metadata analizini özetler. Dokümanlardan %d benzersiz kullanıcı/yazar, %d e-posta adresi, %d farklı yazılım/sürüm ve %d kurum bilgisi tespit edilmiştir. Ayrıca %d adet iç yol/sunucu izi (UNC/şablon yolları) bulunmuştur. Bu veriler, hedef kurumun iç yapısı, kullanıcı isimleri ve yazılım envanteri hakkında pasif istihbarat sağlar; dokümanlar yayımlanmadan önce metadata temizliği yapılmadığını gösterir.",
	recBullets: []string{
		"Dokümanlar yayımlanmadan önce metadata temizliği bir iş akışı adımı haline getirilmeli.",
		"Şablon/köprü alanlarındaki UNC ve yerel yollar (\\\\sunucu\\paylaşım, C:\\...) kaldırılmalı.",
		"Gerçek ad ↔ kullanıcı adı eşleşmesini açığa çıkaran adlandırma alışkanlıkları gözden geçirilmeli.",
		"Belgelerde kişisel e-posta yerine rol-tabanlı kutular (ör. bilgi@kurum) kullanılmalı.",
		"PDF üretiminde yazar/üretici alanını otomatik dolduran araç ayarları kapatılmalı.",
	},
	cleanupSteps: [][2]string{
		{"MS Office (Word / Excel / PowerPoint)", "Dosya → Bilgi → Sorunları Denetle → Belgeyi Denetle → “Belge Özellikleri ve Kişisel Bilgiler”i işaretleyip Tümünü Kaldır, sonra kaydedin."},
		{"LibreOffice (Writer / Calc / Impress)", "Araçlar → Seçenekler → LibreOffice → Kullanıcı Verileri’ni boşaltın; Dosya → Özellikler → “Kaydederken kullanıcı verilerini kullan”ı kapatın / Sıfırla’ya basın."},
		{"Windows (Dosya Gezgini)", "Dosyaya sağ tıklayın → Özellikler → Ayrıntılar → en altta “Özellikleri ve Kişisel Bilgileri Kaldır” → “Olası tüm özellikleri kaldırarak bir kopya oluştur” → Tamam."},
		{"PDF (Adobe Acrobat Pro)", "Araçlar → Gizli Bilgileri Kaldır (Sanitize); veya Dosya → Özellikler → Açıklama sekmesinde Yazar/Üretici alanlarını boşaltın."},
		{"Resimler (fotoğraf)", "Paylaşmadan önce EXIF/GPS konum bilgisini silin (Windows: yukarıdaki Özellikler yöntemi; telefon: “konum bilgisini kaldır”)."},
	},
	glossary: [][2]string{
		{"Metadata", "Bir dosyanın içeriğinden ayrı, onu tanımlayan gömülü bilgi (yazar, tarih, yazılım vb.)."},
		{"Metadata sızıntısı", "Dokümanların metadata'sındaki iç bilgilerin dışarıya açık yayımlanması."},
		{"OSINT", "Açık Kaynak İstihbaratı — herkese açık verilerden bilgi toplama."},
		{"Dork (Google dork)", "Arama motorunda site:/filetype: gibi operatörlerle yapılan hedefli sorgu."},
		{"Alan adı / Alt alan adı", "Tam alan adı/FQDN (ör. www.example.com) ve onun alt alan adı (subdomain)."},
		{"EXIF", "Resim dosyalarındaki gömülü metadata (kamera, yazılım, GPS vb.)."},
		{"GPS", "Resim EXIF'inde bulunabilen coğrafi konum (enlem/boylam) bilgisi."},
		{"UNC yolu", "Windows ağ paylaşım yolu (\\\\sunucu\\paylaşım); iç ağ yapısını ele verir."},
		{"Şablon (Template)", "Ofis dokümanının dayandığı şablon; sıklıkla iç dosya yolu içerir."},
		{"Creator / Producer", "PDF'i oluşturan / üreten yazılımın adı ve sürümü."},
		{"exiftool", "Dosyalardan metadata okuyan ve temizleyen açık kaynak araç."},
		{"KVKK", "Kişisel Verilerin Korunması Kanunu — kişisel verilerin işlenmesini düzenler."},
	},
	pageOf: "Sayfa %d / {nb}",
}

var metaLabelsEN = metaLabels{
	coverTitle: "Metadata Intelligence Report", contents: "Contents",
	hExec: "Executive Summary", hCharts: "Finding Charts", hScope: "Scan Scope & Methodology",
	hTables: "Summary Tables", hCorr: "User – Software / Path Correlation",
	hAppendix: "Findings — Per-File Detail", hRec: "Risks & Recommendations", hGloss: "Glossary",
	mOrg: "Target Organization", mDomain: "Target domain", mDocs: "Documents", mProvider: "Search provider", mDate: "Scan date",
	kDoc: "Documents", kUser: "Users", kEmail: "Emails", kSoftware: "Software", kLeak: "Internal path/server",
	colDocs: "# docs", colType: "Type", colValue: "Value",
	tUsers: "Users / Authors", tSoftware: "Software Inventory", tEmails: "Email Addresses",
	tCompany: "Organization Info", tPathsServers: "Internal Paths & Servers (Sensitive)",
	capPie: "Which categories leaked metadata", capDonut: "Document distribution by file type",
	capUsers: "Top users", capSoftware: "Top software", capEmails: "Top email addresses",
	capTimeline: "Timeline (create/modify dates)",
	corrCaption:  "User ↔ software / operating system / path seen within the same documents.",
	corrUser:     "User", corrSoftware: "Software", corrPathOS: "Path / OS",
	appDocs: "%d documents", appNoMeta: "(no metadata found)", appDisabled: "(Detail appendix disabled.)",
	scopeProvider: "Provider", scopeMethod: "Method",
	scopeMethodText: "Google dork: site:<domain> (filetype:...) → download → exiftool + body text",
	scopeTypes: "Searched types", scopeSubdomains: "Subdomains found", scopeDocStatus: "Document status",
	recIntro: "The metadata in published documents exposes user names, internal network paths, the software inventory and email addresses, providing passive intelligence about the target. Recommended controls:",
	recHowTo: "How to Clean Metadata",
	legalNote: "Legal note: this report is for authorized security testing / OSINT only. Any personal data it contains must be processed lawfully and destroyed when no longer needed.",
	execTemplate: "This report summarizes the metadata analysis of %d documents scanned on the target. The documents revealed %d unique users/authors, %d email addresses, %d distinct software/versions and %d organization records. In addition %d internal path/server traces (UNC/template paths) were found. This data provides passive intelligence about the target's internal structure, user names and software inventory; it shows metadata was not stripped before the documents were published.",
	recBullets: []string{
		"Make metadata stripping a step in the publishing workflow.",
		"Remove UNC and local paths (\\\\server\\share, C:\\...) from template/hyperlink fields.",
		"Review naming habits that reveal the real-name ↔ username mapping.",
		"Prefer role-based mailboxes (e.g. info@org) over personal emails in documents.",
		"Disable tool settings that auto-fill the author/producer field during PDF creation.",
	},
	cleanupSteps: [][2]string{
		{"MS Office (Word / Excel / PowerPoint)", "File → Info → Check for Issues → Inspect Document → tick “Document Properties and Personal Information” → Remove All, then save."},
		{"LibreOffice (Writer / Calc / Impress)", "Tools → Options → LibreOffice → clear User Data; File → Properties → untick “Apply user data” / press Reset."},
		{"Windows (File Explorer)", "Right-click the file → Properties → Details → “Remove Properties and Personal Information” → “Create a copy with all possible properties removed” → OK."},
		{"PDF (Adobe Acrobat Pro)", "Tools → Redact → Sanitize Document; or File → Properties → Description, clear the Author/Producer fields."},
		{"Images (photos)", "Strip EXIF/GPS location before sharing (Windows: the Properties method above; phone: “remove location”)."},
	},
	glossary: [][2]string{
		{"Metadata", "Embedded information describing a file, separate from its content (author, date, software, etc.)."},
		{"Metadata leak", "Internal information in document metadata published openly to the outside."},
		{"OSINT", "Open-Source Intelligence — gathering information from publicly available data."},
		{"Dork (Google dork)", "A targeted search-engine query using operators like site:/filetype:."},
		{"Domain / Subdomain", "A fully-qualified domain (e.g. www.example.com) and its subdomain."},
		{"EXIF", "Embedded metadata in image files (camera, software, GPS, etc.)."},
		{"GPS", "Geographic location (lat/long) that can appear in image EXIF."},
		{"UNC path", "Windows network share path (\\\\server\\share); reveals internal network structure."},
		{"Template", "The template an office document is based on; often contains an internal file path."},
		{"Creator / Producer", "The name and version of the software that created / produced a PDF."},
		{"exiftool", "An open-source tool that reads and cleans metadata from files."},
		{"KVKK / GDPR", "Data-protection law governing the processing of personal data."},
	},
	pageOf: "Page %d / {nb}",
}

func metaCatLabel(lang, cat string) string {
	tr := map[string]string{"user": "Kullanıcı", "software": "Yazılım", "email": "E-posta", "company": "Şirket/Kurum Bilgisi",
		"path": "Yol", "server": "Sunucu", "os": "İşletim Sistemi", "printer": "Yazıcı", "date": "Tarih", "gps": "GPS"}
	en := map[string]string{"user": "User", "software": "Software", "email": "Email", "company": "Company/Org",
		"path": "Path", "server": "Server", "os": "Operating System", "printer": "Printer", "date": "Date", "gps": "GPS"}
	if strings.EqualFold(lang, "en") {
		if v, ok := en[cat]; ok {
			return v
		}
		return cat
	}
	if v, ok := tr[cat]; ok {
		return v
	}
	return cat
}

// ---- builder ----

const (
	mcMargin   = 16.0  // mm, left/right content margin
	mcContentW = 210.0 - 2*mcMargin
)

type metaReport struct {
	pdf   *fpdf.Fpdf
	th    metaTheme
	l     metaLabels
	lang  string
	logoN int // registered-image counter for unique names
}

func setText(pdf *fpdf.Fpdf, c [3]int)  { pdf.SetTextColor(c[0], c[1], c[2]) }
func setFill(pdf *fpdf.Fpdf, c [3]int)  { pdf.SetFillColor(c[0], c[1], c[2]) }
func setDraw(pdf *fpdf.Fpdf, c [3]int)  { pdf.SetDrawColor(c[0], c[1], c[2]) }

// buildMetaReportPDF renders the full branded report.
func buildMetaReportPDF(res *metacollector.ScanResult, opts metaReportOptions) ([]byte, error) {
	agg := metacollector.NewAggregator(res.Findings, res.Documents)
	r := &metaReport{
		pdf:  fpdf.New("P", "mm", "A4", ""),
		th:   resolveMetaTheme(opts),
		l:    metaLabelsFor(opts.Lang),
		lang: opts.Lang,
	}
	pdf := r.pdf
	pdf.AddUTF8Font("DejaVu", "", fontDir+"/DejaVuSans.ttf")
	pdf.AddUTF8Font("DejaVu", "B", fontDir+"/DejaVuSans-Bold.ttf")
	pdf.SetAutoPageBreak(true, 18)
	pdf.AliasNbPages("")

	// Header/footer on every page except the cover (page 1).
	headLeft := firstNonEmpty(opts.TargetOrg, firstNonEmpty(opts.Title, r.l.coverTitle))
	pdf.SetHeaderFunc(func() {
		if pdf.PageNo() <= 1 {
			return
		}
		setDraw(pdf, mcBORDER)
		pdf.SetLineWidth(0.3)
		pdf.RoundedRect(8, 8, 210-16, 297-16, 3, "1234", "D")
		pdf.SetXY(mcMargin, 10)
		pdf.SetFont("DejaVu", "", 8)
		setText(pdf, mcMUTED)
		pdf.CellFormat(mcContentW, 5, pdfSafe(truncRunes(headLeft, 90)), "", 0, "L", false, 0, "")
		setDraw(pdf, r.th.primary)
		pdf.SetLineWidth(0.4)
		pdf.Line(mcMargin, 16, 210-mcMargin, 16)
		pdf.SetY(22)
	})
	pdf.SetFooterFunc(func() {
		if pdf.PageNo() <= 1 {
			return
		}
		pdf.SetY(-14)
		pdf.SetFont("DejaVu", "", 8)
		setText(pdf, mcMUTED)
		pdf.CellFormat(mcContentW, 6, fmt.Sprintf(r.l.pageOf, pdf.PageNo()), "", 0, "R", false, 0, "")
	})

	r.cover(res, opts, agg)
	r.contentsPage()
	r.execSummary(res, agg)
	r.charts(res, agg)
	r.scope(res, agg)
	r.tables(agg)
	r.correlation(agg)
	r.appendix(agg, opts.Appendix)
	r.recommendations()
	r.glossary()

	if err := pdf.Error(); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ---- sections ----

func (r *metaReport) cover(res *metacollector.ScanResult, opts metaReportOptions, agg *metacollector.Aggregator) {
	pdf := r.pdf
	pdf.AddPage()
	pdf.SetY(45)
	if len(opts.Logo) > 0 {
		if t := sniffImageType(opts.Logo); t != "" {
			r.logoN++
			name := "mclogo" + strconv.Itoa(r.logoN)
			pdf.RegisterImageOptionsReader(name, fpdf.ImageOptions{ImageType: t}, bytes.NewReader(opts.Logo))
			if info := pdf.GetImageInfo(name); info != nil && info.Width() > 0 {
				w := 55.0
				h := w * info.Height() / info.Width()
				if h > 45 {
					h = 45
					w = h * info.Width() / info.Height()
				}
				pdf.ImageOptions(name, (210-w)/2, pdf.GetY(), w, h, true, fpdf.ImageOptions{ImageType: t}, 0, "")
				pdf.Ln(6)
			}
		}
	}
	// accent bar
	setFill(pdf, r.th.primary)
	pdf.Rect(mcMargin, pdf.GetY(), 35, 1.4, "F")
	pdf.Ln(6)
	// title
	pdf.SetFont("DejaVu", "B", 26)
	setText(pdf, mcINK)
	pdf.MultiCell(mcContentW, 12, pdfSafe(firstNonEmpty(opts.Title, r.l.coverTitle)), "", "L", false)
	if opts.TargetOrg != "" {
		pdf.SetFont("DejaVu", "B", 13)
		setText(pdf, r.th.primary)
		pdf.MultiCell(mcContentW, 7, pdfSafe(opts.TargetOrg), "", "L", false)
	}
	pdf.Ln(8)
	setDraw(pdf, mcBORDER)
	pdf.SetLineWidth(0.3)
	pdf.Line(mcMargin, pdf.GetY(), 210-mcMargin, pdf.GetY())
	pdf.Ln(5)
	// meta rows
	rows := [][2]string{}
	if opts.TargetOrg != "" {
		rows = append(rows, [2]string{r.l.mOrg, opts.TargetOrg})
	}
	rows = append(rows,
		[2]string{r.l.mDocs, strconv.Itoa(len(res.Documents))},
		[2]string{r.l.mProvider, res.Provider},
		[2]string{r.l.mDate, monthYear(res.StartedAt)},
	)
	r.kvRows(rows, 45)
}

func (r *metaReport) contentsPage() {
	pdf := r.pdf
	pdf.AddPage()
	r.h1(r.l.contents)
	items := []string{r.l.hExec, r.l.hCharts, r.l.hScope, r.l.hTables, r.l.hCorr, r.l.hAppendix, r.l.hRec, r.l.hGloss}
	pdf.SetFont("DejaVu", "", 11)
	setText(pdf, mcINK)
	for _, it := range items {
		pdf.CellFormat(mcContentW, 8, pdfSafe(it), "B", 1, "L", false, 0, "")
	}
}

func (r *metaReport) execSummary(res *metacollector.ScanResult, agg *metacollector.Aggregator) {
	pdf := r.pdf
	pdf.AddPage()
	r.h1(r.l.hExec)
	c := agg.Cats()
	leak := c["path"] + c["server"]
	pdf.SetFont("DejaVu", "", 9.5)
	setText(pdf, mcINK)
	pdf.MultiCell(mcContentW, 5.2, pdfSafe(fmt.Sprintf(r.l.execTemplate,
		len(res.Documents), c["user"], c["email"], c["software"], c["company"], leak)), "", "L", false)
	pdf.Ln(3)
	r.kpiCards([][2]string{
		{strconv.Itoa(len(res.Documents)), r.l.kDoc},
		{strconv.Itoa(c["user"]), r.l.kUser},
		{strconv.Itoa(c["email"]), r.l.kEmail},
		{strconv.Itoa(c["software"]), r.l.kSoftware},
		{strconv.Itoa(leak), r.l.kLeak},
	})
}

func (r *metaReport) charts(res *metacollector.ScanResult, agg *metacollector.Aggregator) {
	pdf := r.pdf
	pdf.AddPage()
	r.h1(r.l.hCharts)
	cats := agg.Cats()

	// Category-leak pie (date excluded, only non-zero categories).
	var pieLabels []string
	var pieVals []float64
	for _, cat := range metacollector.CategoryOrder {
		if cat == "date" {
			continue
		}
		if n := cats[cat]; n > 0 {
			pieLabels = append(pieLabels, metaCatLabel(r.lang, cat))
			pieVals = append(pieVals, float64(n))
		}
	}
	if len(pieVals) >= 2 {
		r.chartTitle(r.l.capPie)
		r.drawPieWithLegend(pieLabels, pieVals, false)
	}

	// Filetype donut.
	ftCounts := map[string]int{}
	for _, d := range res.Documents {
		ft := strings.ToLower(d.Filetype)
		if ft == "" {
			ft = "?"
		}
		ftCounts[ft]++
	}
	if len(ftCounts) >= 2 {
		labels, vals := topCounts(ftCounts, 10)
		r.chartTitle(r.l.capDonut)
		r.drawPieWithLegend(labels, vals, true)
	}

	// Horizontal bars.
	for _, spec := range []struct {
		cat, cap string
	}{{"user", r.l.capUsers}, {"software", r.l.capSoftware}, {"email", r.l.capEmails}} {
		top := agg.Top(spec.cat, 10)
		if len(top) == 0 {
			continue
		}
		r.chartTitle(spec.cap)
		r.drawHBars(top)
	}

	// Timeline.
	years := agg.Years()
	if len(years) > 0 {
		r.chartTitle(r.l.capTimeline)
		r.drawTimeline(years)
	}
}

func (r *metaReport) scope(res *metacollector.ScanResult, agg *metacollector.Aggregator) {
	pdf := r.pdf
	pdf.AddPage()
	r.h1(r.l.hScope)
	// filetypes present
	ftSet := map[string]bool{}
	for _, d := range res.Documents {
		ft := strings.ToLower(d.Filetype)
		if ft == "" {
			ft = "?"
		}
		ftSet[ft] = true
	}
	fts := keysSorted(ftSet)
	// subdomains (distinct FQDN with findings/docs)
	fqdns := map[string]bool{}
	for _, d := range res.Documents {
		fqdns[netlocOf(d.URL)] = true
	}
	var statusParts []string
	for _, k := range keysSortedInt(res.StatusCount) {
		statusParts = append(statusParts, fmt.Sprintf("%s=%d", k, res.StatusCount[k]))
	}
	rows := [][2]string{
		{r.l.scopeProvider, res.Provider},
		{r.l.scopeMethod, r.l.scopeMethodText},
		{r.l.scopeTypes, strings.Join(fts, ", ")},
		{r.l.scopeSubdomains, strconv.Itoa(len(fqdns))},
		{r.l.scopeDocStatus, strings.Join(statusParts, ", ")},
	}
	r.kvRows(rows, 42)
}

func (r *metaReport) tables(agg *metacollector.Aggregator) {
	pdf := r.pdf
	pdf.AddPage()
	r.h1(r.l.hTables)
	specs := []struct {
		cat, title string
	}{{"user", r.l.tUsers}, {"software", r.l.tSoftware}, {"email", r.l.tEmails}, {"company", r.l.tCompany}}
	for _, s := range specs {
		rows := agg.Top(s.cat, 60)
		if len(rows) == 0 {
			continue
		}
		r.h2(s.title)
		data := make([][]string, 0, len(rows))
		for _, vc := range rows {
			data = append(data, []string{vc.Value, strconv.Itoa(vc.Docs)})
		}
		r.dataTable([]string{metaCatLabel(r.lang, s.cat), r.l.colDocs}, data, []float64{mcContentW - 26, 26})
	}
	paths := agg.Top("path", 60)
	servers := agg.Top("server", 60)
	if len(paths) > 0 || len(servers) > 0 {
		r.h2(r.l.tPathsServers)
		var data [][]string
		typePath := metaCatLabel(r.lang, "path")
		typeServer := metaCatLabel(r.lang, "server")
		for _, vc := range paths {
			data = append(data, []string{typePath, vc.Value, strconv.Itoa(vc.Docs)})
		}
		for _, vc := range servers {
			data = append(data, []string{typeServer, vc.Value, strconv.Itoa(vc.Docs)})
		}
		r.dataTable([]string{r.l.colType, r.l.colValue, r.l.colDocs}, data, []float64{26, mcContentW - 52, 26})
	}
}

func (r *metaReport) correlation(agg *metacollector.Aggregator) {
	corr := agg.Correlation([]string{"software", "os", "path"}, 15)
	// keep only users with at least one correlated value
	type crow struct{ user, sw, pathos string }
	var rows []crow
	for _, c := range corr {
		user := c[0].(string)
		rel := c[1].(map[string][]string)
		sw := joinN(rel["software"], 4)
		pathos := joinN(append(append([]string{}, rel["path"]...), rel["os"]...), 2)
		if sw == "" && pathos == "" {
			continue
		}
		if sw == "" {
			sw = "-"
		}
		if pathos == "" {
			pathos = "-"
		}
		rows = append(rows, crow{user, sw, pathos})
	}
	if len(rows) == 0 {
		return
	}
	pdf := r.pdf
	pdf.AddPage()
	r.h1(r.l.hCorr)
	pdf.SetFont("DejaVu", "", 8)
	setText(pdf, mcMUTED)
	pdf.MultiCell(mcContentW, 4.5, pdfSafe(r.l.corrCaption), "", "L", false)
	pdf.Ln(1)
	var data [][]string
	for _, row := range rows {
		data = append(data, []string{row.user, row.sw, row.pathos})
	}
	r.dataTable([]string{r.l.corrUser, r.l.corrSoftware, r.l.corrPathOS}, data, []float64{42, 72, mcContentW - 114})
}

func (r *metaReport) appendix(agg *metacollector.Aggregator, mode string) {
	pdf := r.pdf
	pdf.AddPage()
	r.h1(r.l.hAppendix)
	if mode == "none" {
		pdf.SetFont("DejaVu", "", 8)
		setText(pdf, mcMUTED)
		pdf.MultiCell(mcContentW, 4.5, pdfSafe(r.l.appDisabled), "", "L", false)
		return
	}
	byDoc := agg.ByDocument()
	// group docURLs by netloc
	groups := map[string][]string{}
	for url := range byDoc {
		groups[netlocOf(url)] = append(groups[netlocOf(url)], url)
	}
	for _, nl := range keysSortedStr(groups) {
		urls := groups[nl]
		sort.Strings(urls)
		r.h2(nl)
		pdf.SetFont("DejaVu", "", 8)
		setText(pdf, mcMUTED)
		pdf.MultiCell(mcContentW, 4.5, pdfSafe(fmt.Sprintf(r.l.appDocs, len(urls))), "", "L", false)
		for _, url := range urls {
			doc := byDoc[url]
			r.h3(urlPathOf(url))
			var kv [][2]string
			for _, cat := range metacollector.CategoryOrder {
				if vals, ok := doc[cat].([]string); ok && len(vals) > 0 {
					kv = append(kv, [2]string{metaCatLabel(r.lang, cat), strings.Join(vals, ", ")})
				}
			}
			if len(kv) == 0 {
				pdf.SetFont("DejaVu", "", 8)
				setText(pdf, mcMUTED)
				pdf.MultiCell(mcContentW, 4.5, pdfSafe(r.l.appNoMeta), "", "L", false)
			} else {
				r.kvTable(kv, 32)
			}
			pdf.Ln(1.5)
		}
	}
}

func (r *metaReport) recommendations() {
	pdf := r.pdf
	pdf.AddPage()
	r.h1(r.l.hRec)
	pdf.SetFont("DejaVu", "", 9.5)
	setText(pdf, mcINK)
	pdf.MultiCell(mcContentW, 5.2, pdfSafe(r.l.recIntro), "", "L", false)
	pdf.Ln(1)
	for _, b := range r.l.recBullets {
		x := pdf.GetX()
		pdf.SetX(x + 2)
		pdf.MultiCell(mcContentW-2, 5, pdfSafe("•  "+b), "", "L", false)
	}
	pdf.Ln(2)
	r.h2(r.l.recHowTo)
	var kv [][2]string
	for _, s := range r.l.cleanupSteps {
		kv = append(kv, [2]string{s[0], s[1]})
	}
	r.kvTable(kv, 50)
	pdf.Ln(2)
	pdf.SetFont("DejaVu", "", 8)
	setText(pdf, mcMUTED)
	pdf.MultiCell(mcContentW, 4.5, pdfSafe(r.l.legalNote), "", "L", false)
}

func (r *metaReport) glossary() {
	pdf := r.pdf
	pdf.AddPage()
	r.h1(r.l.hGloss)
	r.kvTable(r.l.glossary, 40)
}

// ---- primitives ----

func (r *metaReport) h1(s string) {
	pdf := r.pdf
	pdf.SetFont("DejaVu", "B", 17)
	setText(pdf, r.th.dark)
	pdf.MultiCell(mcContentW, 9, pdfSafe(s), "", "L", false)
	pdf.Ln(2)
}

func (r *metaReport) h2(s string) {
	pdf := r.pdf
	if pdf.GetY() > 250 {
		pdf.AddPage()
	}
	pdf.SetFont("DejaVu", "B", 12)
	setText(pdf, r.th.primary)
	pdf.Ln(3)
	pdf.MultiCell(mcContentW, 7, pdfSafe(s), "", "L", false)
	pdf.Ln(1)
}

func (r *metaReport) h3(s string) {
	pdf := r.pdf
	if pdf.GetY() > 255 {
		pdf.AddPage()
	}
	pdf.SetFont("DejaVu", "B", 10)
	setText(pdf, mcINK)
	pdf.Ln(1)
	pdf.MultiCell(mcContentW, 5.5, pdfSafe(s), "", "L", false)
}

func (r *metaReport) chartTitle(s string) {
	pdf := r.pdf
	if pdf.GetY() > 235 {
		pdf.AddPage()
	}
	pdf.Ln(2)
	pdf.SetFont("DejaVu", "B", 10.5)
	setText(pdf, mcINK)
	pdf.MultiCell(mcContentW, 6, pdfSafe(s), "", "L", false)
	pdf.Ln(1)
}

// kvRows draws label/value rows with a shaded label column (cover + scope).
func (r *metaReport) kvRows(rows [][2]string, labelW float64) {
	pdf := r.pdf
	valueW := mcContentW - labelW
	for _, row := range rows {
		label, value := row[0], row[1]
		if strings.TrimSpace(value) == "" {
			value = "—"
		}
		pdf.SetFont("DejaVu", "B", 8.5)
		nL := len(pdf.SplitLines([]byte(pdfSafe(label)), labelW-3))
		pdf.SetFont("DejaVu", "", 8.5)
		nV := len(pdf.SplitLines([]byte(pdfSafe(value)), valueW-3))
		n := nL
		if nV > n {
			n = nV
		}
		if n < 1 {
			n = 1
		}
		rowH := float64(n)*4.6 + 2.2
		if pdf.GetY()+rowH > 280 {
			pdf.AddPage()
		}
		x, y := pdf.GetX(), pdf.GetY()
		setFill(pdf, mcKVBG)
		pdf.Rect(x, y, labelW, rowH, "F")
		pdf.SetFont("DejaVu", "B", 8.5)
		setText(pdf, r.th.dark)
		pdf.SetXY(x+1.5, y+1.4)
		pdf.MultiCell(labelW-3, 4.6, pdfSafe(label), "", "L", false)
		pdf.SetFont("DejaVu", "", 8.5)
		setText(pdf, mcINK)
		pdf.SetXY(x+labelW+1.5, y+1.4)
		pdf.MultiCell(valueW-3, 4.6, pdfSafe(value), "", "L", false)
		setDraw(pdf, mcBORDER)
		pdf.SetLineWidth(0.2)
		pdf.Line(x, y+rowH, x+mcContentW, y+rowH)
		pdf.SetXY(x, y+rowH)
	}
	pdf.Ln(2)
}

// kvTable draws a bordered label/value table (appendix, cleanup, glossary).
func (r *metaReport) kvTable(rows [][2]string, labelW float64) {
	pdf := r.pdf
	valueW := mcContentW - labelW
	for _, row := range rows {
		label, value := row[0], row[1]
		pdf.SetFont("DejaVu", "B", 8.5)
		nL := len(pdf.SplitLines([]byte(pdfSafe(label)), labelW-3))
		pdf.SetFont("DejaVu", "", 8.5)
		nV := len(pdf.SplitLines([]byte(pdfSafe(value)), valueW-3))
		n := nL
		if nV > n {
			n = nV
		}
		if n < 1 {
			n = 1
		}
		rowH := float64(n)*4.4 + 2.0
		if pdf.GetY()+rowH > 278 {
			pdf.AddPage()
		}
		x, y := pdf.GetX(), pdf.GetY()
		setFill(pdf, mcKVBG)
		pdf.Rect(x, y, labelW, rowH, "F")
		setDraw(pdf, mcBORDER)
		pdf.SetLineWidth(0.2)
		pdf.Rect(x, y, mcContentW, rowH, "D")
		pdf.SetFont("DejaVu", "B", 8.5)
		setText(pdf, r.th.dark)
		pdf.SetXY(x+1.5, y+1.2)
		pdf.MultiCell(labelW-3, 4.4, pdfSafe(label), "", "L", false)
		pdf.SetFont("DejaVu", "", 8.5)
		setText(pdf, mcINK)
		pdf.SetXY(x+labelW+1.5, y+1.2)
		pdf.MultiCell(valueW-3, 4.4, pdfSafe(value), "", "L", false)
		pdf.SetXY(x, y+rowH)
	}
}

// dataTable draws a header + zebra rows table (summary tables, correlation).
func (r *metaReport) dataTable(headers []string, rows [][]string, widths []float64) {
	pdf := r.pdf
	drawHeader := func() {
		x, y := pdf.GetX(), pdf.GetY()
		setFill(pdf, mcSLATE)
		pdf.Rect(x, y, mcContentW, 6.5, "F")
		setDraw(pdf, r.th.primary)
		pdf.SetLineWidth(0.5)
		pdf.Line(x, y, x+mcContentW, y)
		pdf.SetFont("DejaVu", "B", 9)
		setText(pdf, mcWHITE)
		cx := x
		for i, h := range headers {
			pdf.SetXY(cx+1.5, y+1.4)
			pdf.MultiCell(widths[i]-3, 4, pdfSafe(h), "", "L", false)
			cx += widths[i]
		}
		pdf.SetXY(x, y+6.5)
	}
	drawHeader()
	zebra := false
	for _, row := range rows {
		pdf.SetFont("DejaVu", "", 8.5)
		n := 1
		for i, c := range row {
			if lc := len(pdf.SplitLines([]byte(pdfSafe(c)), widths[i]-3)); lc > n {
				n = lc
			}
		}
		rowH := float64(n)*4.4 + 1.6
		if pdf.GetY()+rowH > 280 {
			pdf.AddPage()
			drawHeader()
			zebra = false
		}
		x, y := pdf.GetX(), pdf.GetY()
		if zebra {
			setFill(pdf, mcZEBRA)
			pdf.Rect(x, y, mcContentW, rowH, "F")
		}
		zebra = !zebra
		setText(pdf, mcINK)
		pdf.SetFont("DejaVu", "", 8.5)
		cx := x
		for i, c := range row {
			pdf.SetXY(cx+1.5, y+1.0)
			pdf.MultiCell(widths[i]-3, 4.4, pdfSafe(c), "", "L", false)
			cx += widths[i]
		}
		setDraw(pdf, mcBORDER)
		pdf.SetLineWidth(0.2)
		pdf.Line(x, y+rowH, x+mcContentW, y+rowH)
		pdf.SetXY(x, y+rowH)
	}
	pdf.Ln(2)
}

// kpiCards draws n equal-width stat cards with a themed top rule.
func (r *metaReport) kpiCards(items [][2]string) {
	pdf := r.pdf
	n := len(items)
	if n == 0 {
		return
	}
	gap := 3.0
	cw := (mcContentW - gap*float64(n-1)) / float64(n)
	ch := 20.0
	x0, y0 := pdf.GetX(), pdf.GetY()
	if y0+ch > 280 {
		pdf.AddPage()
		x0, y0 = pdf.GetX(), pdf.GetY()
	}
	for i, it := range items {
		x := x0 + float64(i)*(cw+gap)
		setDraw(pdf, mcBORDER)
		pdf.SetLineWidth(0.3)
		pdf.Rect(x, y0, cw, ch, "D")
		setDraw(pdf, r.th.primary)
		pdf.SetLineWidth(1.2)
		pdf.Line(x, y0, x+cw, y0)
		pdf.SetFont("DejaVu", "B", 17)
		setText(pdf, r.th.primary)
		pdf.SetXY(x, y0+4)
		pdf.CellFormat(cw, 9, pdfSafe(it[0]), "", 0, "C", false, 0, "")
		pdf.SetFont("DejaVu", "", 7.5)
		setText(pdf, mcMUTED)
		pdf.SetXY(x, y0+13)
		pdf.CellFormat(cw, 4, pdfSafe(it[1]), "", 0, "C", false, 0, "")
	}
	pdf.SetXY(x0, y0+ch+3)
}

// drawHBars draws a horizontal bar chart (top values, largest first).
func (r *metaReport) drawHBars(items []metacollector.ValCount) {
	pdf := r.pdf
	rowH := 5.6
	total := rowH*float64(len(items)) + 4
	if pdf.GetY()+total > 282 {
		pdf.AddPage()
	}
	maxV := 1
	for _, it := range items {
		if it.Docs > maxV {
			maxV = it.Docs
		}
	}
	labelW := 55.0
	barMax := mcContentW - labelW - 16
	x0 := pdf.GetX()
	y := pdf.GetY() + 1
	for _, it := range items {
		pdf.SetFont("DejaVu", "", 8)
		setText(pdf, mcINK)
		pdf.SetXY(x0, y)
		pdf.CellFormat(labelW-2, rowH, pdfSafe(truncRunes(it.Value, 42)), "", 0, "L", false, 0, "")
		bw := barMax * float64(it.Docs) / float64(maxV)
		if bw < 0.6 {
			bw = 0.6
		}
		setFill(pdf, r.th.primary)
		pdf.Rect(x0+labelW, y+1, bw, rowH-2, "F")
		pdf.SetFont("DejaVu", "", 7.5)
		setText(pdf, mcCVAL)
		pdf.SetXY(x0+labelW+bw+1.5, y)
		pdf.CellFormat(14, rowH, strconv.Itoa(it.Docs), "", 0, "L", false, 0, "")
		y += rowH
	}
	pdf.SetXY(x0, y+2)
}

// drawTimeline draws a vertical bar chart of documents per year.
func (r *metaReport) drawTimeline(years map[string]int) {
	pdf := r.pdf
	keys := make([]string, 0, len(years))
	for k := range years {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	chartH := 32.0
	if pdf.GetY()+chartH+10 > 282 {
		pdf.AddPage()
	}
	x0 := pdf.GetX()
	y0 := pdf.GetY() + 2
	maxV := 1
	for _, v := range years {
		if v > maxV {
			maxV = v
		}
	}
	n := len(keys)
	slot := mcContentW / float64(n)
	barW := slot * 0.6
	if barW > 16 {
		barW = 16
	}
	base := y0 + chartH
	for i, k := range keys {
		v := years[k]
		bh := chartH * float64(v) / float64(maxV)
		bx := x0 + float64(i)*slot + (slot-barW)/2
		setFill(pdf, r.th.bar2)
		pdf.Rect(bx, base-bh, barW, bh, "F")
		pdf.SetFont("DejaVu", "", 7)
		setText(pdf, mcCVAL)
		pdf.SetXY(x0+float64(i)*slot, base-bh-4)
		pdf.CellFormat(slot, 3.5, strconv.Itoa(v), "", 0, "C", false, 0, "")
		setText(pdf, mcMUTED)
		pdf.SetXY(x0+float64(i)*slot, base+0.5)
		pdf.CellFormat(slot, 4, pdfSafe(k), "", 0, "C", false, 0, "")
	}
	setDraw(pdf, mcCGRID)
	pdf.SetLineWidth(0.2)
	pdf.Line(x0, base, x0+mcContentW, base)
	pdf.SetXY(x0, base+6)
}

// drawPieWithLegend draws a pie (or donut) with a swatch legend to the right.
func (r *metaReport) drawPieWithLegend(labels []string, values []float64, donut bool) {
	pdf := r.pdf
	size := 46.0
	if pdf.GetY()+size+4 > 282 {
		pdf.AddPage()
	}
	x0 := pdf.GetX()
	y0 := pdf.GetY() + 2
	cx := x0 + size/2
	cy := y0 + size/2
	radius := size/2 - 2

	total := 0.0
	for _, v := range values {
		total += v
	}
	if total <= 0 {
		return
	}
	start := -90.0
	for i, v := range values {
		sweep := v / total * 360
		col := r.th.palette[i%len(r.th.palette)]
		setFill(pdf, col)
		pts := []fpdf.PointType{{X: cx, Y: cy}}
		steps := int(math.Max(2, sweep/3))
		for s := 0; s <= steps; s++ {
			ang := (start + sweep*float64(s)/float64(steps)) * math.Pi / 180
			pts = append(pts, fpdf.PointType{X: cx + radius*math.Cos(ang), Y: cy + radius*math.Sin(ang)})
		}
		pdf.Polygon(pts, "F")
		start += sweep
	}
	if donut {
		setFill(pdf, mcWHITE)
		pdf.Circle(cx, cy, radius*0.55, "F")
	}

	// Legend
	lx := x0 + size + 6
	ly := y0
	pdf.SetFont("DejaVu", "", 8)
	for i, lab := range labels {
		col := r.th.palette[i%len(r.th.palette)]
		setFill(pdf, col)
		pdf.Rect(lx, ly+0.6, 3.2, 3.2, "F")
		setText(pdf, mcINK)
		pct := int(values[i] * 100 / total)
		pdf.SetXY(lx+4.5, ly)
		pdf.CellFormat(mcContentW-size-12, 4.4, pdfSafe(fmt.Sprintf("%s  (%d, %%%d)", truncRunes(lab, 28), int(values[i]), pct)), "", 0, "L", false, 0, "")
		ly += 4.8
	}
	bottom := y0 + size
	if ly > bottom {
		bottom = ly
	}
	pdf.SetXY(x0, bottom+3)
}

// ---- CSV / JSON ----

func buildMetaReportCSV(res *metacollector.ScanResult) []byte {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	_ = w.Write([]string{"url", "filetype", "category", "tag", "value"})
	ftByURL := map[string]string{}
	for _, d := range res.Documents {
		ftByURL[d.URL] = d.Filetype
	}
	rows := make([]metacollector.Finding, len(res.Findings))
	copy(rows, res.Findings)
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].DocURL != rows[j].DocURL {
			return rows[i].DocURL < rows[j].DocURL
		}
		if rows[i].Category != rows[j].Category {
			return rows[i].Category < rows[j].Category
		}
		return rows[i].Value < rows[j].Value
	})
	for _, f := range rows {
		_ = w.Write([]string{f.DocURL, ftByURL[f.DocURL], f.Category, f.Tag, f.Value})
	}
	w.Flush()
	return buf.Bytes()
}

func buildMetaReportJSON(res *metacollector.ScanResult) []byte {
	agg := metacollector.NewAggregator(res.Findings, res.Documents)
	out := map[string]interface{}{
		"summary":     agg.SummaryAll(),
		"by_user":     agg.ByUser(),
		"by_document": agg.ByDocument(),
		"by_value":    agg.ByValue(),
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	return b
}

// ---- helpers ----

func sniffImageType(b []byte) string {
	if len(b) >= 8 && b[0] == 0x89 && b[1] == 'P' && b[2] == 'N' && b[3] == 'G' {
		return "PNG"
	}
	if len(b) >= 3 && b[0] == 0xFF && b[1] == 0xD8 && b[2] == 0xFF {
		return "JPG"
	}
	if len(b) >= 3 && b[0] == 'G' && b[1] == 'I' && b[2] == 'F' {
		return "GIF"
	}
	return ""
}

func truncRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

func monthYear(iso string) string {
	if t, err := time.Parse(time.RFC3339, iso); err == nil {
		return t.Format("01.2006")
	}
	if len(iso) >= 7 {
		return iso[:7]
	}
	return iso
}

func netlocOf(rawURL string) string {
	u := rawURL
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
	}
	if i := strings.IndexAny(u, "/?#"); i >= 0 {
		u = u[:i]
	}
	if u == "" {
		return "?"
	}
	return u
}

func urlPathOf(rawURL string) string {
	u := rawURL
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
	}
	if i := strings.IndexAny(u, "/"); i >= 0 {
		p := u[i:]
		if p == "" {
			return "/"
		}
		return p
	}
	return "/"
}

func joinN(vals []string, n int) string {
	seen := map[string]bool{}
	var uniq []string
	for _, v := range vals {
		if !seen[v] {
			seen[v] = true
			uniq = append(uniq, v)
		}
	}
	sort.Strings(uniq)
	if len(uniq) > n {
		uniq = uniq[:n]
	}
	return strings.Join(uniq, ", ")
}

func topCounts(m map[string]int, n int) ([]string, []float64) {
	type kv struct {
		k string
		v int
	}
	var arr []kv
	for k, v := range m {
		arr = append(arr, kv{k, v})
	}
	sort.SliceStable(arr, func(i, j int) bool {
		if arr[i].v != arr[j].v {
			return arr[i].v > arr[j].v
		}
		return arr[i].k < arr[j].k
	})
	if len(arr) > n {
		arr = arr[:n]
	}
	labels := make([]string, 0, len(arr))
	vals := make([]float64, 0, len(arr))
	for _, e := range arr {
		labels = append(labels, e.k)
		vals = append(vals, float64(e.v))
	}
	return labels, vals
}

func keysSorted(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func keysSortedStr(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func keysSortedInt(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
