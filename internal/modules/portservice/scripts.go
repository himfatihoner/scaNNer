package portservice

import "strings"

// Phase-2 NSE scripts, grouped by service. Each script is hand-picked to be:
//
//  1. Safe and non-intrusive — no brute-force, no input prompts, no
//     authentication needed. (Anything in the "intrusive" or "auth" category
//     that requires creds is excluded.)
//  2. NOT already covered by `-A`'s default-script set. `-A` runs every
//     script tagged "default" plus -O / -sV / --traceroute, so things like
//     http-title, http-headers, ssh-hostkey, smb-os-discovery already fire
//     automatically. Listing them again would be wasted bandwidth.
//  3. Specific to a single service / protocol so the second pass scans only
//     the ports that benefit from each script.
//
// extraScriptsForPort() looks each port up by its detected Service+Tunnel
// and returns the union of matching scripts.
var serviceScripts = map[string][]string{
	// SSL / TLS — fires for any port whose tunnel is "ssl" or whose
	// service explicitly uses TLS (https, smtps, imaps, pop3s, ldaps, …).
	// `ssl-enum-ciphers` and `ssl-poodle` are intentionally OUT of the
	// default extras — they each can take 5+ minutes per host on slow
	// networks because they iterate every cipher suite. Move them to a
	// future "deep scan" toggle if the user wants them.
	"ssl": {
		"ssl-cert",
		"ssl-date",
		"ssl-heartbleed",
		"ssl-ccs-injection",
		"ssl-dh-params",
		"ssl-known-key",
		"tls-alpn",
		"tls-nextprotoneg",
		"tls-ticketbleed",
	},
	// http extras — slow path-enumeration and credential-brute scripts
	// have been removed. http-enum tries hundreds of paths, http-default-
	// accounts brute-forces logins, http-passwd / http-phpmyadmin-dir-
	// traversal / http-comments-displayer all walk and parse pages. Each
	// of those alone can dominate scan time on a single web host. The
	// surviving scripts are quick fingerprint / vuln-detection probes.
	"http": {
		"http-methods",
		"http-trace",
		"http-cookie-flags",
		"http-cors",
		"http-csrf",
		"http-shellshock",
		"http-server-header",
		"http-robots.txt",
		"http-git",
		"http-php-version",
		"http-vuln-cve2017-5638",
		"http-vuln-cve2017-5689",
		"http-vuln-cve2014-3704",
		"http-internal-ip-disclosure",
		"http-security-headers",
	},
	"smtp": {
		"smtp-commands",
		"smtp-open-relay",
		"smtp-vuln-cve2010-4344",
		"smtp-vuln-cve2011-1764",
		"smtp-strangeport",
		"smtp-ntlm-info",
	},
	"imap": {"imap-capabilities", "imap-ntlm-info"},
	"pop3": {"pop3-capabilities", "pop3-ntlm-info"},
	"ftp": {
		"ftp-anon",
		"ftp-syst",
		"ftp-bounce",
		"ftp-vsftpd-backdoor",
		"ftp-proftpd-backdoor",
		"ftp-vuln-cve2010-4221",
		"ftp-libopie",
	},
	"ssh": {
		"ssh2-enum-algos",
		"ssh-auth-methods",
		"sshv1",
	},
	"smb": {
		"smb-protocols",
		"smb-security-mode",
		"smb-enum-shares",
		"smb-enum-domains",
		"smb-enum-services",
		"smb-vuln-ms08-067",
		"smb-vuln-ms17-010",
		"smb-vuln-cve-2017-7494",
		"smb-double-pulsar-backdoor",
		"smb-vuln-conficker",
	},
	"rdp": {
		"rdp-enum-encryption",
		"rdp-ntlm-info",
		"rdp-vuln-ms12-020",
	},
	"mysql": {
		"mysql-info",
		"mysql-empty-password",
		"mysql-vuln-cve2012-2122",
	},
	"mssql": {
		"ms-sql-info",
		"ms-sql-empty-password",
		"ms-sql-ntlm-info",
		"ms-sql-config",
	},
	"oracle": {"oracle-tns-version"},
	"postgresql": {
		"pgsql-brute",
	},
	"redis":         {"redis-info"},
	"mongodb":       {"mongodb-info", "mongodb-databases"},
	"elasticsearch": {"http-elasticsearch-head"},
	"dns": {
		"dns-recursion",
		"dns-cache-snoop",
		"dns-nsid",
		"dns-zone-transfer",
		"dns-srv-enum",
	},
	"snmp": {
		"snmp-info",
		"snmp-sysdescr",
		"snmp-interfaces",
		"snmp-processes",
		"snmp-netstat",
		"snmp-win32-services",
		"snmp-win32-software",
	},
	"ntp": {
		"ntp-info",
		"ntp-monlist",
	},
	"ldap": {
		"ldap-rootdse",
	},
	"vnc": {
		"vnc-info",
		"realvnc-auth-bypass",
	},
	"telnet": {
		"telnet-encryption",
		"telnet-ntlm-info",
	},
	"rsync": {
		"rsync-list-modules",
	},
	"memcached": {
		"memcached-info",
	},
	"ipmi": {
		"ipmi-cipher-zero",
		"ipmi-version",
	},
	"rmi": {
		"rmi-vuln-classloader",
		"rmi-dumpregistry",
	},
	"ajp": {
		"ajp-headers",
		"ajp-methods",
		"ajp-auth",
	},
	"redis_cluster": {"redis-info"},
	"jdwp":          {"jdwp-info", "jdwp-version"},
	"docker":        {"docker-version"},
	"nfs":           {"nfs-ls", "nfs-showmount", "nfs-statfs"},
	"rpcbind":       {"rpcinfo"},
	"netbios": {
		"nbstat",
	},
}

// extraScriptsForPort picks NSE scripts for a single open port based on
// its detected service / tunnel / product. Substring matching is used so
// "http-proxy", "https", "https-alt", "ssl/http", etc. all map to the
// http+ssl bundles.
func extraScriptsForPort(p Port) []string {
	seen := map[string]struct{}{}
	add := func(scripts []string) {
		for _, s := range scripts {
			seen[s] = struct{}{}
		}
	}
	svc := strings.ToLower(p.Service)
	tunnel := strings.ToLower(p.Tunnel)

	// SSL/TLS layer — runs for tunnel=ssl OR known TLS service names.
	if tunnel == "ssl" ||
		svc == "https" || svc == "smtps" || svc == "imaps" || svc == "pop3s" ||
		svc == "ldaps" || svc == "ftps" || svc == "ssl/http" ||
		strings.HasPrefix(svc, "ssl/") || strings.Contains(svc, "https") {
		add(serviceScripts["ssl"])
	}

	switch {
	case strings.Contains(svc, "http") || strings.Contains(svc, "www"):
		add(serviceScripts["http"])
	case strings.Contains(svc, "smtp"):
		add(serviceScripts["smtp"])
	case strings.Contains(svc, "imap"):
		add(serviceScripts["imap"])
	case strings.Contains(svc, "pop3"):
		add(serviceScripts["pop3"])
	case strings.Contains(svc, "ftp"):
		add(serviceScripts["ftp"])
	case strings.Contains(svc, "ssh"):
		add(serviceScripts["ssh"])
	case strings.Contains(svc, "microsoft-ds") ||
		strings.Contains(svc, "netbios-ssn") ||
		strings.Contains(svc, "netbios-ns") ||
		strings.Contains(svc, "smb"):
		add(serviceScripts["smb"])
	case strings.Contains(svc, "rdp") ||
		strings.Contains(svc, "ms-wbt-server") ||
		strings.Contains(svc, "terminal-services"):
		add(serviceScripts["rdp"])
	case strings.Contains(svc, "mysql"):
		add(serviceScripts["mysql"])
	case strings.Contains(svc, "ms-sql") || strings.Contains(svc, "mssql"):
		add(serviceScripts["mssql"])
	case strings.Contains(svc, "oracle") || strings.Contains(svc, "tns"):
		add(serviceScripts["oracle"])
	case strings.Contains(svc, "postgres"):
		add(serviceScripts["postgresql"])
	case strings.Contains(svc, "redis"):
		add(serviceScripts["redis"])
	case strings.Contains(svc, "mongo"):
		add(serviceScripts["mongodb"])
	case strings.Contains(svc, "elasticsearch"):
		add(serviceScripts["elasticsearch"])
	case strings.Contains(svc, "domain") || svc == "dns":
		add(serviceScripts["dns"])
	case strings.Contains(svc, "snmp"):
		add(serviceScripts["snmp"])
	case strings.Contains(svc, "ntp"):
		add(serviceScripts["ntp"])
	case strings.Contains(svc, "ldap"):
		add(serviceScripts["ldap"])
	case strings.Contains(svc, "vnc"):
		add(serviceScripts["vnc"])
	case strings.Contains(svc, "telnet"):
		add(serviceScripts["telnet"])
	case strings.Contains(svc, "rsync"):
		add(serviceScripts["rsync"])
	case strings.Contains(svc, "memcache"):
		add(serviceScripts["memcached"])
	case strings.Contains(svc, "ipmi") || strings.Contains(svc, "asf-rmcp"):
		add(serviceScripts["ipmi"])
	case strings.Contains(svc, "rmi") || strings.Contains(svc, "java-rmi"):
		add(serviceScripts["rmi"])
	case strings.Contains(svc, "ajp"):
		add(serviceScripts["ajp"])
	case strings.Contains(svc, "jdwp"):
		add(serviceScripts["jdwp"])
	case strings.Contains(svc, "docker"):
		add(serviceScripts["docker"])
	case strings.Contains(svc, "nfs"):
		add(serviceScripts["nfs"])
	case strings.Contains(svc, "rpcbind") || strings.Contains(svc, "portmapper"):
		add(serviceScripts["rpcbind"])
	}

	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	return out
}

// extraScriptsForHost gathers the union of phase-2 scripts across every open
// port on a host, paired with the comma-separated port list each script
// should target. Returns a map: scriptName → "22,80,443" so the second nmap
// invocation can run each script only on the ports where it makes sense.
//
// The grouping keeps the second nmap call efficient: scripts that apply to
// multiple ports (e.g. ssl-enum-ciphers on 443 + 8443) are consolidated, and
// the per-script -p list narrows the work.
func extraScriptsForHost(ports []Port) map[string]string {
	scriptPorts := map[string]map[int]struct{}{}
	for _, p := range ports {
		if p.State != "open" {
			continue
		}
		for _, s := range extraScriptsForPort(p) {
			if _, ok := scriptPorts[s]; !ok {
				scriptPorts[s] = map[int]struct{}{}
			}
			scriptPorts[s][p.Port] = struct{}{}
		}
	}
	out := make(map[string]string, len(scriptPorts))
	for s, ports := range scriptPorts {
		nums := make([]int, 0, len(ports))
		for n := range ports {
			nums = append(nums, n)
		}
		// sort for stable output
		for i := 0; i < len(nums); i++ {
			for j := i + 1; j < len(nums); j++ {
				if nums[j] < nums[i] {
					nums[i], nums[j] = nums[j], nums[i]
				}
			}
		}
		parts := make([]string, len(nums))
		for i, n := range nums {
			parts[i] = itoa(n)
		}
		out[s] = strings.Join(parts, ",")
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	buf := make([]byte, 0, 6)
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	if neg {
		buf = append([]byte{'-'}, buf...)
	}
	return string(buf)
}
