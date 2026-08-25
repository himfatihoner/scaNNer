package handlers

import (
	"fmt"
	"strings"
)

// TLS/SSL findings come from the sslscan module with English titles and
// descriptions and no captured HTTP request/response. This file gives them (a)
// Turkish title + description for the bounded, known set of sslscan findings so
// TR reports read fully in Turkish, and (b) a command-based Proof of Concept
// (nmap + openssl) since there is no raw HTTP exchange to show.

// tlsFindingTR maps an sslscan finding title (English) → {Turkish title,
// Turkish description}. Descriptions are kept generic-but-specific to the
// finding type; the exact observed detail (cipher names, dates) is shown
// verbatim in the PoC's "observed" section.
var tlsFindingTR = map[string][2]string{
	"No Modern TLS":                                 {"Modern TLS Desteği Yok", "Sunucu TLS 1.2 veya TLS 1.3'ün hiçbirini desteklemiyor. Bağlantı tümüyle şifresiz değildir; ancak yalnızca eski ve kırılabilir protokoller (TLS 1.0/1.1, SSLv3 gibi) üzerinden şifrelenir. Bu protokoller MITM/şifre çözme saldırılarına açık olduğundan güvenli kabul edilmez."},
	"TLS 1.3 Not Supported":                         {"TLS 1.3 Desteklenmiyor", "Sunucu, en güncel ve en güvenli sürüm olan TLS 1.3'ü desteklemiyor."},
	"TLS 1.1":                                       {"TLS 1.1 Destekleniyor", "Eski TLS 1.1 protokolü sunuluyor; modern şifre desteği yoktur ve RFC 8996 ile kullanımdan kaldırılmıştır."},
	"TLS 1.0":                                       {"TLS 1.0 Destekleniyor", "Eski TLS 1.0 protokolü sunuluyor; bilinen zayıflıkları vardır ve RFC 8996 ile kullanımdan kaldırılmıştır."},
	"3DES Ciphers Supported":                        {"3DES Şifre Takımları Destekleniyor", "64-bit bloklu 3DES şifresi sunuluyor ve Sweet32 doğum günü saldırısına açıktır."},
	"CBC without Forward Secrecy Ciphers Supported": {"İleri Gizlilik Olmadan CBC Şifreleri", "Statik RSA ile CBC modu şifreleri sunuluyor; Lucky13 zamanlama saldırısına açıktır ve ileri gizlilik (PFS) sağlamaz."},
	"Static RSA Key Exchange Ciphers Supported":     {"Statik RSA Anahtar Değişimi Şifreleri", "İleri gizlilik sağlamayan şifreler sunuluyor; sunucunun özel anahtarı ele geçirilirse kaydedilmiş geçmiş trafik çözülebilir."},
	"RC4":                                           {"RC4 Şifreleri Destekleniyor", "Kriptografik olarak zayıf ve kullanımdan kaldırılmış RC4 akış şifresi sunuluyor."},
	"Incomplete Certificate Chain":                  {"Eksik Sertifika Zinciri", "Sunucu ara (intermediate) sertifikaları sunmuyor; sertifika zincirinin doğrulaması başarısız oluyor."},
	"No OCSP Stapling":                              {"OCSP Stapling Yok", "Sunucu TLS el sıkışmasında OCSP yanıtı sunmuyor; sertifikanın iptal durumu istemcinin ayrıca sorgulamasını gerektiriyor."},
	"Expired Certificate":                           {"Süresi Dolmuş Sertifika", "Sunucu sertifikasının geçerlilik süresi dolmuş; istemciler güvenlik uyarısı alır."},
	"Certificate Expiring Soon":                     {"Sertifikanın Süresi Yakında Doluyor", "Sunucu sertifikasının geçerlilik süresi kısa süre içinde dolacak."},
	"Self-Signed Certificate":                       {"Kendinden İmzalı Sertifika", "Sertifika güvenilir bir sertifika otoritesi (CA) tarafından imzalanmamış."},
	"Hostname Mismatch":                             {"Alan Adı Uyuşmazlığı", "Sertifikadaki alan adı, bağlanılan ana bilgisayar adıyla eşleşmiyor."},
}

// tlsPrefixTR translates dynamic titles ("Weak Key (2048-bit)", "Weak
// Signature (SHA1)", "Certificate expired on …") by prefix.
var tlsPrefixTR = []struct{ prefix, tr, desc string }{
	{"Weak Signature", "Zayıf İmza Algoritması", "Sertifika, zayıf bir imza algoritması (örn. SHA-1/MD5) ile imzalanmış."},
	{"Weak Key", "Zayıf Anahtar Uzunluğu", "Sertifika, günümüz standartlarına göre zayıf uzunlukta bir anahtar kullanıyor."},
	{"Certificate expired", "Süresi Dolmuş Sertifika", "Sunucu sertifikasının geçerlilik süresi dolmuş."},
	{"Certificate expires", "Sertifikanın Süresi Yakında Doluyor", "Sunucu sertifikasının geçerlilik süresi kısa süre içinde dolacak."},
}

// tlsTitleTR returns the Turkish title + description for a TLS finding title, or
// empty strings when it isn't a recognized sslscan finding (caller keeps the
// original English text).
func tlsTitleTR(title string) (trTitle, trDesc string) {
	if v, ok := tlsFindingTR[title]; ok {
		return v[0], v[1]
	}
	// Per-version weak-cipher rows: "Weak Cipher Suites (TLS 1.0)". Translate the
	// label but preserve the "(TLS x.y)" version suffix so the report stays
	// specific to the version the ciphers were offered on.
	if strings.HasPrefix(title, "Weak Cipher Suites") {
		trTitle = "Zayıf Şifre Takımları"
		if suffix := strings.TrimSpace(strings.TrimPrefix(title, "Weak Cipher Suites")); suffix != "" {
			trTitle += " " + suffix // suffix is already "(TLS 1.0)"
		}
		return trTitle, "Bu TLS sürümünde ileri gizlilik sağlamayan veya kriptografik olarak zayıf şifre takımları sunuluyor (örn. RC4, DES/3DES-Sweet32, EXPORT/FREAK, CBC/Lucky13, statik RSA). Sunulan zayıf şifreler ve etkilenen sürüm, bulgu açıklamasında ve PoC bölümünde listelenmiştir."
	}
	for _, p := range tlsPrefixTR {
		if strings.HasPrefix(title, p.prefix) {
			return p.tr, p.desc
		}
	}
	return "", ""
}

// tlsPoCReal renders the PoC from the real tool run the sslscan module captured
// for this finding: the exact command executed and that command's console
// output. This is the reproducible, "what the tool actually showed" evidence
// the operator asked for. Falls back gracefully if only one half is present.
func tlsPoCReal(v GlobalVuln, lang string) string {
	en := strings.EqualFold(lang, "en")
	cmd := strings.TrimSpace(v.PoCCommand)
	out := strings.TrimRight(v.PoCOutput, "\n")

	var b strings.Builder
	if cmd != "" {
		if en {
			b.WriteString("# Command run:\n")
		} else {
			b.WriteString("# Çalıştırılan komut:\n")
		}
		b.WriteString("$ " + cmd + "\n")
	}
	if strings.TrimSpace(out) != "" {
		if en {
			b.WriteString("\n# Command output:\n")
		} else {
			b.WriteString("\n# Komut çıktısı:\n")
		}
		b.WriteString(out + "\n")
	}
	// If the module somehow captured a command but no output, still show the
	// observed detail so the PoC isn't just a bare command line.
	if strings.TrimSpace(out) == "" {
		obs := strings.TrimSpace(v.Description)
		if obs == "" {
			obs = strings.TrimSpace(v.Evidence)
		}
		if obs != "" {
			if en {
				b.WriteString("\n# Observed by the scan:\n")
			} else {
				b.WriteString("\n# Tarama sırasında gözlemlenen:\n")
			}
			b.WriteString(obs + "\n")
		}
	}
	return b.String()
}

// tlsPoC builds a reproduction PoC for a TLS/SSL finding. sslscan captures no
// HTTP exchange, so instead of a raw request/response we give the operator the
// exact commands to reproduce the observation — nmap's ssl-enum-ciphers (the
// single most useful check: it lists every offered protocol + cipher suite with
// a grade) and an openssl certificate dump — plus the concrete detail the scan
// observed. host/port come from the finding (port inherited from the sslscan
// host object; defaults to 443).
func tlsPoC(v GlobalVuln, lang string) string {
	host := normalizeAsset(v.Host)
	port := strings.TrimSpace(v.Port)
	if port == "" {
		port = "443"
	}
	en := strings.EqualFold(lang, "en")

	var b strings.Builder
	if en {
		b.WriteString("# Enumerate the offered TLS protocols and cipher suites (confirms the finding):\n")
	} else {
		b.WriteString("# Sunucunun sunduğu TLS protokollerini ve şifre takımlarını listeler (bulguyu doğrular):\n")
	}
	b.WriteString(fmt.Sprintf("nmap -Pn -sV --script ssl-enum-ciphers -p %s %s\n\n", port, host))

	if en {
		b.WriteString("# Inspect the served certificate (chain, validity, signature, hostname):\n")
	} else {
		b.WriteString("# Sunulan sertifikayı inceler (zincir, geçerlilik, imza, alan adı):\n")
	}
	b.WriteString(fmt.Sprintf("openssl s_client -connect %s:%s -servername %s </dev/null 2>/dev/null | openssl x509 -noout -text\n", host, port, host))

	// Concrete detail the scan already observed — the "console log" evidence.
	obs := strings.TrimSpace(v.Description)
	if obs == "" {
		obs = strings.TrimSpace(v.Evidence)
	}
	if obs != "" {
		if en {
			b.WriteString("\n# Observed by the scan:\n")
		} else {
			b.WriteString("\n# Tarama sırasında gözlemlenen:\n")
		}
		b.WriteString(obs + "\n")
	}
	return b.String()
}
