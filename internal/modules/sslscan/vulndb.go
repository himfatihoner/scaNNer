package sslscan

import "strings"

// Severity levels
type Severity string

const (
	SevCritical Severity = "CRITICAL"
	SevHigh     Severity = "HIGH"
	SevMedium   Severity = "MEDIUM"
	SevLow      Severity = "LOW"
	SevInfo     Severity = "INFO"
)

// SeverityScore returns a numeric score for sorting
func SeverityScore(s Severity) int {
	switch s {
	case SevCritical:
		return 5
	case SevHigh:
		return 4
	case SevMedium:
		return 3
	case SevLow:
		return 2
	case SevInfo:
		return 1
	default:
		return 0
	}
}

// VulnProtocol describes a vulnerable TLS/SSL protocol version
type VulnProtocol struct {
	Name     string
	ID       uint16
	Severity Severity
	CVEs     []string
	Reason   string
}

// VulnerableProtocols is the known-bad protocol list
var VulnerableProtocols = []VulnProtocol{
	{
		Name: "SSL 2.0", ID: 0x0002, Severity: SevCritical,
		CVEs:   []string{"CVE-2011-1473", "CVE-2016-0800"},
		Reason: "Completely broken. Vulnerable to DROWN attack.",
	},
	{
		Name: "SSL 3.0", ID: 0x0300, Severity: SevCritical,
		CVEs:   []string{"CVE-2014-3566"},
		Reason: "Vulnerable to POODLE attack.",
	},
	{
		Name: "TLS 1.0", ID: 0x0301, Severity: SevHigh,
		CVEs:   []string{"CVE-2011-3389", "CVE-2015-0204"},
		Reason: "Vulnerable to BEAST and FREAK attacks. Deprecated by RFC 8996.",
	},
	{
		Name: "TLS 1.1", ID: 0x0302, Severity: SevMedium,
		CVEs:   []string{"CVE-2015-0204"},
		Reason: "No modern cipher support. Deprecated by RFC 8996.",
	},
}

// CipherCategory is a vulnerability class that groups individual ciphers
type CipherCategory struct {
	Name        string // short label: "3DES", "RC4", "NULL", etc.
	Severity    Severity
	CVEs        []string
	Description string
}

// All known cipher vulnerability categories, ordered by severity
var cipherCategories = []CipherCategory{
	{Name: "NULL Encryption", Severity: SevCritical,
		CVEs: []string{"N/A"}, Description: "No encryption. Traffic is plaintext."},
	{Name: "EXPORT Ciphers", Severity: SevCritical,
		CVEs: []string{"CVE-2015-0204", "CVE-2015-4000"}, Description: "Export-grade 40/56-bit keys. FREAK / Logjam attacks."},
	{Name: "Anonymous DH", Severity: SevCritical,
		CVEs: []string{"N/A"}, Description: "No server authentication. Trivial MitM."},
	{Name: "DES", Severity: SevHigh,
		CVEs: []string{"CVE-2016-2183"}, Description: "56-bit key, trivially breakable."},
	{Name: "RC4", Severity: SevHigh,
		CVEs: []string{"CVE-2013-2566", "CVE-2015-2808"}, Description: "Known biases in keystream. Bar Mitzvah attack."},
	{Name: "3DES", Severity: SevMedium,
		CVEs: []string{"CVE-2016-2183"}, Description: "64-bit block cipher. Sweet32 birthday attack."},
	{Name: "CBC without Forward Secrecy", Severity: SevLow,
		CVEs: []string{"CVE-2013-0169"}, Description: "CBC mode with static RSA. Lucky13 timing attack, no PFS."},
	{Name: "Static RSA Key Exchange", Severity: SevLow,
		CVEs: []string{"N/A"}, Description: "No forward secrecy. Passive decryption if server key is compromised."},
}

// ClassifyCipher returns the vulnerability category for a cipher suite name.
// Returns nil if the cipher is considered safe.
func ClassifyCipher(name string) *CipherCategory {
	switch {
	case strings.Contains(name, "NULL"):
		return &cipherCategories[0]
	case strings.Contains(name, "EXPORT"):
		return &cipherCategories[1]
	case strings.Contains(name, "anon"):
		return &cipherCategories[2]
	case strings.Contains(name, "_DES_") && !strings.Contains(name, "3DES") && !strings.Contains(name, "EDE"):
		return &cipherCategories[3]
	case strings.Contains(name, "RC4"):
		return &cipherCategories[4]
	case strings.Contains(name, "3DES") || strings.Contains(name, "EDE"):
		return &cipherCategories[5]
	case strings.Contains(name, "CBC"):
		if !strings.Contains(name, "ECDHE") && !strings.Contains(name, "DHE") {
			return &cipherCategories[6]
		}
	case strings.Contains(name, "_RSA_") && !strings.Contains(name, "ECDHE") && !strings.Contains(name, "DHE"):
		if strings.Contains(name, "GCM") {
			return &cipherCategories[7]
		}
	}
	return nil
}
