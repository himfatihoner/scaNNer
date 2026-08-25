package handlers

import "strings"

// Bilingual vulnerability-class knowledge base (Task: per-vuln report export).
//
// Scanners capture a finding's identity (name, severity, host, sometimes CVE /
// evidence / raw request-response) but almost never the narrative fields a
// formal pentest report needs: preconditions, impact, a standard remediation,
// a representative CVSS vector, or a CWE. This KB supplies those per
// vulnerability CLASS, in Turkish and English. The report assembler
// (vuln_report.go) uses scanner-captured values when present and falls back to
// the KB for the blanks — Preconditions/Impact always come from the KB (never
// captured), the rest only when the module didn't provide them.
//
// Mirrors the moduleinfo.go ModuleDoc pattern: a curated static map, keyed by a
// normalized class that classifyVuln derives from the module + title.

type kbText struct {
	Preconditions string
	Impact        string
	Remediation   string
	Description   string
	CVSSVector    string // representative CVSS v3.1 base vector for the class
	CWE           string
}

type kbEntry struct {
	Name string // human class label (EN), for logging/debug
	TR   kbText
	EN   kbText
}

// vulnKB maps a class key → bilingual narrative. Keep entries concise (1–2
// sentences per field); the report joins them with the scanner's concrete data.
var vulnKB = map[string]kbEntry{
	"sqli": {
		Name: "SQL Injection",
		TR: kbText{
			Preconditions: "Hedef uygulamaya ağ erişimi ve kullanıcı girdisinin doğrudan SQL sorgusuna dahil edildiği en az bir parametreye erişim.",
			Impact:        "Saldırgan veritabanını okuyabilir/değiştirebilir, kimlik doğrulamayı atlayabilir, hassas verileri sızdırabilir ve bazı durumlarda işletim sistemi komutları çalıştırarak sunucuyu ele geçirebilir.",
			Remediation:   "Parametreli sorgular (prepared statement) veya ORM kullanın; girdileri tür ve biçim olarak doğrulayın; veritabanı hesabına en az ayrıcalık verin; WAF ile ek katman ekleyin.",
			Description:   "Kullanıcı girdisinin yeterince temizlenmeden SQL sorgusuna eklenmesi, saldırganın sorgu mantığını değiştirmesine olanak tanır.",
			CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			CWE:           "CWE-89",
		},
		EN: kbText{
			Preconditions: "Network access to the target application and reach to at least one parameter whose value is concatenated into a SQL query.",
			Impact:        "An attacker can read/modify the database, bypass authentication, exfiltrate sensitive data, and in some cases execute OS commands to take over the server.",
			Remediation:   "Use parameterized queries (prepared statements) or an ORM; validate input by type and format; grant the database account least privilege; add a WAF as defense in depth.",
			Description:   "User input is placed into a SQL query without sufficient sanitization, letting an attacker alter the query logic.",
			CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			CWE:           "CWE-89",
		},
	},
	"xss": {
		Name: "Cross-Site Scripting (XSS)",
		TR: kbText{
			Preconditions: "Kullanıcı girdisinin yansıtıldığı/saklandığı bir uygulama ve kurbanı tetiklenen sayfaya yönlendirebilme (yansıyan XSS için) veya girdinin kalıcı depolanması (kalıcı XSS için).",
			Impact:        "Kurbanın tarayıcısında betik çalıştırılarak oturum çerezleri çalınabilir, işlem yapılabilir, sayfa içeriği değiştirilebilir veya kimlik avı gerçekleştirilebilir.",
			Remediation:   "Çıktıyı bağlama uygun şekilde kodlayın (HTML/JS/URL); Content-Security-Policy uygulayın; çerezlere HttpOnly ekleyin; girdileri beyaz liste ile doğrulayın.",
			Description:   "Uygulama, kullanıcı girdisini yeterince kodlamadan HTML/JavaScript bağlamına yazarak saldırganın tarayıcıda betik çalıştırmasına izin verir.",
			CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
			CWE:           "CWE-79",
		},
		EN: kbText{
			Preconditions: "An application that reflects/stores user input and the ability to lure a victim to the triggering page (reflected) or to persist the payload (stored).",
			Impact:        "Script executes in the victim's browser: session cookies can be stolen, actions performed, page content altered, or phishing staged.",
			Remediation:   "Context-aware output encoding (HTML/JS/URL); enforce a Content-Security-Policy; set HttpOnly on cookies; validate input against an allow-list.",
			Description:   "The application writes user input into an HTML/JavaScript context without adequate encoding, allowing an attacker to run script in the browser.",
			CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
			CWE:           "CWE-79",
		},
	},
	"ssti": {
		Name: "Server-Side Template Injection",
		TR: kbText{
			Preconditions: "Kullanıcı girdisinin sunucu tarafı şablon motoruna (Jinja2, Twig, Freemarker vb.) ifade olarak geçirildiği bir uç nokta.",
			Impact:        "Şablon motoru üzerinden sunucuda kod çalıştırılabilir; bu genellikle tam sunucu ele geçirme ile sonuçlanır.",
			Remediation:   "Kullanıcı girdisini şablonlara ifade olarak geçirmeyin; sandbox'lı/mantıksız (logic-less) şablon kullanın; girdileri katı biçimde doğrulayın.",
			Description:   "Kullanıcı girdisi bir sunucu tarafı şablonuna ifade olarak yerleştirilir ve motor tarafından değerlendirilerek kod çalıştırmaya yol açar.",
			CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			CWE:           "CWE-1336",
		},
		EN: kbText{
			Preconditions: "An endpoint that passes user input as an expression into a server-side template engine (Jinja2, Twig, Freemarker, etc.).",
			Impact:        "Code execution on the server via the template engine, typically resulting in full server takeover.",
			Remediation:   "Never pass user input into templates as an expression; use sandboxed/logic-less templates; strictly validate input.",
			Description:   "User input is embedded into a server-side template as an expression and evaluated by the engine, leading to code execution.",
			CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			CWE:           "CWE-1336",
		},
	},
	"open-redirect": {
		Name: "Open Redirect",
		TR: kbText{
			Preconditions: "Yönlendirme hedefini kullanıcı kontrollü bir parametreden alan ve doğrulamayan bir uç nokta.",
			Impact:        "Kurbanlar güvenilir alan adı üzerinden saldırgan denetimli sitelere yönlendirilerek kimlik avı ve oturum/token sızıntısı gerçekleştirilebilir.",
			Remediation:   "Yönlendirme hedeflerini sunucu tarafı beyaz liste ile sınırlayın; harici mutlak URL'lere izin vermeyin; göreli yollar kullanın.",
			Description:   "Uygulama, doğrulamadan kullanıcı denetimli bir değere yönlendirme yaparak güvenilir alanın kötüye kullanılmasına izin verir.",
			CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
			CWE:           "CWE-601",
		},
		EN: kbText{
			Preconditions: "An endpoint that takes its redirect target from a user-controlled parameter and does not validate it.",
			Impact:        "Victims are redirected via the trusted domain to attacker-controlled sites, enabling phishing and session/token leakage.",
			Remediation:   "Constrain redirect targets with a server-side allow-list; reject external absolute URLs; prefer relative paths.",
			Description:   "The application redirects to a user-controlled value without validation, allowing abuse of the trusted domain.",
			CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
			CWE:           "CWE-601",
		},
	},
	"cors": {
		Name: "CORS Misconfiguration",
		TR: kbText{
			Preconditions: "Kaynağı yansıtan veya çok geniş izin veren bir CORS politikası ve kimlik bilgisi (çerez/token) ile erişilen bir uç nokta.",
			Impact:        "Saldırgan denetimli bir köken, kurbanın kimliğiyle hassas yanıtları okuyabilir; veri sızıntısına yol açar.",
			Remediation:   "Access-Control-Allow-Origin değerini katı bir beyaz listeye sabitleyin; Origin'i yansıtmayın; kimlik bilgili isteklerde '*' ve credentials birlikte kullanılmamalı.",
			Description:   "Aşırı izin veren CORS başlıkları, güvenilmeyen kökenlerin kimlik bilgili yanıtları okumasına olanak tanır.",
			CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N",
			CWE:           "CWE-942",
		},
		EN: kbText{
			Preconditions: "A CORS policy that reflects the Origin or is overly permissive, on an endpoint accessed with credentials (cookie/token).",
			Impact:        "An attacker-controlled origin can read sensitive responses as the victim, leading to data leakage.",
			Remediation:   "Pin Access-Control-Allow-Origin to a strict allow-list; never reflect the Origin; never combine '*' with credentials.",
			Description:   "Overly permissive CORS headers let untrusted origins read credentialed responses.",
			CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N",
			CWE:           "CWE-942",
		},
	},
	"missing-security-header": {
		Name: "Missing / Weak Security Header",
		TR: kbText{
			Preconditions: "HTTP yanıtlarında güvenlik başlıklarının (HSTS, CSP, X-Frame-Options vb.) eksik veya zayıf yapılandırılmış olması.",
			Impact:        "Clickjacking, MIME sniffing, karışık içerik ve aktarım güvenliği zayıflıkları gibi istemci tarafı saldırılara zemin hazırlar.",
			Remediation:   "Strict-Transport-Security, Content-Security-Policy, X-Content-Type-Options: nosniff ve çerçeveleme koruması (frame-ancestors/X-Frame-Options) başlıklarını ekleyin.",
			Description:   "Yanıtlarda önerilen güvenlik başlıkları eksik olduğundan tarayıcı tarafı korumalar devre dışı kalır.",
			CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
			CWE:           "CWE-693",
		},
		EN: kbText{
			Preconditions: "HTTP responses missing or weakly configuring security headers (HSTS, CSP, X-Frame-Options, etc.).",
			Impact:        "Enables client-side attacks such as clickjacking, MIME sniffing, mixed content, and transport-security weaknesses.",
			Remediation:   "Add Strict-Transport-Security, Content-Security-Policy, X-Content-Type-Options: nosniff, and framing protection (frame-ancestors/X-Frame-Options).",
			Description:   "Recommended security headers are absent, leaving browser-side protections disabled.",
			CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
			CWE:           "CWE-693",
		},
	},
	"weak-tls": {
		Name: "Weak SSL/TLS Configuration",
		TR: kbText{
			Preconditions: "Zayıf protokol (SSLv3/TLS1.0/1.1), zayıf şifreleme takımı veya geçersiz/zayıf sertifika sunan bir TLS servisi ve ağ üzerinde araya girebilme.",
			Impact:        "Araya girme (MITM) ile trafiğin çözülmesi veya değiştirilmesi, kimlik bilgisi ve oturum bilgisi sızıntısı mümkün olabilir.",
			Remediation:   "Yalnızca TLS 1.2+ etkinleştirin; zayıf şifre takımlarını devre dışı bırakın; güçlü anahtar ve güncel sertifika kullanın; HSTS uygulayın.",
			Description:   "Sunucu, zayıf protokol/şifreleme veya sertifika yapılandırması sunarak aktarım güvenliğini zayıflatır.",
			CVSSVector:    "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N",
			CWE:           "CWE-326",
		},
		EN: kbText{
			Preconditions: "A TLS service offering a weak protocol (SSLv3/TLS1.0/1.1), weak cipher suite, or invalid/weak certificate, plus a network position to intercept.",
			Impact:        "Man-in-the-middle decryption or tampering of traffic, leaking credentials and session data.",
			Remediation:   "Enable only TLS 1.2+; disable weak cipher suites; use strong keys and a current certificate; enforce HSTS.",
			Description:   "The server offers weak protocol/cipher or certificate configuration, weakening transport security.",
			CVSSVector:    "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N",
			CWE:           "CWE-326",
		},
	},
	"subdomain-takeover": {
		Name: "Subdomain Takeover",
		TR: kbText{
			Preconditions: "Bir DNS kaydının (CNAME) artık sahiplenilmemiş/serbest bir üçüncü taraf servise işaret etmesi ve o servisin saldırganca talep edilebilmesi.",
			Impact:        "Saldırgan alt alan adını ele geçirerek üzerinde içerik yayımlayabilir; kimlik avı, çerez çalma ve marka itibar zararı oluşturabilir.",
			Remediation:   "Kullanılmayan DNS kayıtlarını kaldırın; servis kaldırma süreçlerinde DNS temizliğini zorunlu kılın; sahiplik doğrulaması yapın.",
			Description:   "Bir alt alan adı, artık var olmayan bir kaynağa işaret eder ve saldırgan o kaynağı talep ederek alt alanı ele geçirir.",
			CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
			CWE:           "CWE-350",
		},
		EN: kbText{
			Preconditions: "A DNS record (CNAME) pointing to an unclaimed/dangling third-party service that the attacker can register.",
			Impact:        "The attacker takes over the subdomain to host content, enabling phishing, cookie theft, and brand damage.",
			Remediation:   "Remove stale DNS records; enforce DNS cleanup in service-decommission workflows; verify resource ownership.",
			Description:   "A subdomain points to a resource that no longer exists, and an attacker claims that resource to seize the subdomain.",
			CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
			CWE:           "CWE-350",
		},
	},
	"jwt-weakness": {
		Name: "JSON Web Token Weakness",
		TR: kbText{
			Preconditions: "Uygulamanın JWT ile kimlik doğrulaması yapması ve zayıf imza (alg=none, zayıf sır, algoritma karışıklığı) kabul etmesi.",
			Impact:        "Saldırgan geçerli token üreterek kimliğe bürünebilir, yetki yükseltebilir ve kimlik doğrulamayı atlatabilir.",
			Remediation:   "Güçlü ve gizli imza anahtarı kullanın; 'none' algoritmasını reddedin; algoritmayı sunucu tarafında sabitleyin; token'ları süre ve kapsam ile sınırlayın.",
			Description:   "JWT doğrulaması zayıf yapılandırıldığından saldırgan kendi geçerli token'ını üretebilir.",
			CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
			CWE:           "CWE-347",
		},
		EN: kbText{
			Preconditions: "The application authenticates with JWTs and accepts a weak signature (alg=none, weak secret, algorithm confusion).",
			Impact:        "The attacker forges valid tokens to impersonate users, escalate privileges, and bypass authentication.",
			Remediation:   "Use a strong secret signing key; reject the 'none' algorithm; pin the algorithm server-side; scope and time-limit tokens.",
			Description:   "JWT verification is weakly configured, letting an attacker mint their own valid token.",
			CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
			CWE:           "CWE-347",
		},
	},
	"kerberoasting": {
		Name: "Kerberoasting",
		TR: kbText{
			Preconditions: "Etki alanında geçerli bir hesap ve SPN'e sahip servis hesaplarının bulunması.",
			Impact:        "Servis hesaplarının TGS biletleri çevrimdışı kırılarak parola elde edilebilir; yatay/dikey hareket ve etki alanı ele geçirme riski doğar.",
			Remediation:   "Servis hesaplarına uzun/rastgele parolalar (gMSA) atayın; gereksiz SPN'leri kaldırın; AES şifrelemeyi zorunlu kılın; anormal TGS taleplerini izleyin.",
			Description:   "Saldırgan SPN'li hesaplar için TGS bileti talep eder ve çevrimdışı parola kırma ile servis hesabı kimlik bilgisini elde eder.",
			CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
			CWE:           "CWE-522",
		},
		EN: kbText{
			Preconditions: "A valid domain account and the existence of service accounts that have SPNs.",
			Impact:        "TGS tickets for service accounts are cracked offline to recover passwords, enabling lateral/vertical movement and domain compromise.",
			Remediation:   "Assign long/random passwords (gMSA) to service accounts; remove unnecessary SPNs; enforce AES encryption; monitor abnormal TGS requests.",
			Description:   "The attacker requests TGS tickets for SPN accounts and cracks them offline to obtain service-account credentials.",
			CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
			CWE:           "CWE-522",
		},
	},
	"asreproast": {
		Name: "AS-REP Roasting",
		TR: kbText{
			Preconditions: "Etki alanında 'Kerberos ön kimlik doğrulaması gerektirmez' olarak işaretlenmiş hesapların bulunması.",
			Impact:        "Bu hesapların AS-REP yanıtları çevrimdışı kırılarak parolaları elde edilebilir ve etki alanına erişim genişletilebilir.",
			Remediation:   "Ön kimlik doğrulamayı tüm hesaplarda zorunlu kılın; güçlü parola politikası uygulayın; bu tür hesapları düzenli denetleyin.",
			Description:   "Ön kimlik doğrulama devre dışı hesaplar için AS-REP yanıtı istenip çevrimdışı kırılarak parola elde edilir.",
			CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
			CWE:           "CWE-522",
		},
		EN: kbText{
			Preconditions: "Accounts in the domain flagged as 'does not require Kerberos pre-authentication'.",
			Impact:        "AS-REP responses for those accounts are cracked offline to recover passwords, expanding domain access.",
			Remediation:   "Require pre-authentication on all accounts; enforce a strong password policy; audit such accounts regularly.",
			Description:   "AS-REP responses are requested for pre-auth-disabled accounts and cracked offline to recover passwords.",
			CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
			CWE:           "CWE-522",
		},
	},
	"cache-poisoning": {
		Name: "Web Cache Poisoning",
		TR: kbText{
			Preconditions: "Önbelleğe alınan yanıtların, önbellek anahtarına dahil olmayan (unkeyed) girdilerden etkilenmesi.",
			Impact:        "Zehirlenmiş önbellek üzerinden birden çok kullanıcıya kötü amaçlı içerik/başlık sunulabilir; XSS, yönlendirme ve hizmet aksatma mümkündür.",
			Remediation:   "Önbellek anahtarına etkili tüm girdileri dahil edin; unkeyed başlıklara güvenmeyin; önbellek davranışını sıkı yapılandırın.",
			Description:   "Anahtarlanmamış girdilerin yanıtı etkilemesi, saldırganın paylaşılan önbelleği zehirlemesine olanak tanır.",
			CVSSVector:    "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:L",
			CWE:           "CWE-444",
		},
		EN: kbText{
			Preconditions: "Cached responses are influenced by inputs not included in the cache key (unkeyed inputs).",
			Impact:        "A poisoned cache serves malicious content/headers to many users, enabling XSS, redirection, and denial of service.",
			Remediation:   "Include all response-affecting inputs in the cache key; do not trust unkeyed headers; tighten cache configuration.",
			Description:   "Unkeyed inputs affect the response, allowing an attacker to poison the shared cache.",
			CVSSVector:    "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:L",
			CWE:           "CWE-444",
		},
	},
	"graphql": {
		Name: "GraphQL Misconfiguration",
		TR: kbText{
			Preconditions: "İçe bakış (introspection) açık veya derinlik/karmaşıklık sınırı olmayan bir GraphQL uç noktası.",
			Impact:        "Şema keşfi ile saldırı yüzeyi açığa çıkar; iç içe sorgularla hizmet aksatma ve yetkisiz veri erişimi mümkün olabilir.",
			Remediation:   "Üretimde introspection'ı kapatın; sorgu derinliği/karmaşıklığı ve oran sınırı uygulayın; alan bazında yetkilendirme yapın.",
			Description:   "GraphQL uç noktası güvenli yapılandırılmadığından şema açığa çıkar ve kaynak tüketimi/veri erişimi kötüye kullanılabilir.",
			CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L",
			CWE:           "CWE-200",
		},
		EN: kbText{
			Preconditions: "A GraphQL endpoint with introspection enabled or no depth/complexity limits.",
			Impact:        "Schema disclosure exposes the attack surface; nested queries enable denial of service and unauthorized data access.",
			Remediation:   "Disable introspection in production; enforce query depth/complexity and rate limits; apply field-level authorization.",
			Description:   "The GraphQL endpoint is insecurely configured, exposing the schema and allowing resource/data abuse.",
			CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L",
			CWE:           "CWE-200",
		},
	},
	"auth-bypass": {
		Name: "Authentication / Authorization Weakness",
		TR: kbText{
			Preconditions: "Yetkilendirme kontrollerinin eksik/yetersiz olduğu bir uç nokta ve düşük ayrıcalıklı bir erişim.",
			Impact:        "Yetki yükseltme, başka kullanıcıların verilerine erişim (IDOR) veya kimlik doğrulamayı tümüyle atlatma mümkün olabilir.",
			Remediation:   "Sunucu tarafında nesne düzeyinde yetkilendirme uygulayın; oturum ve rol kontrollerini her istekte doğrulayın; güvenli varsayılanlar kullanın.",
			Description:   "Erişim denetimi zayıf uygulandığından saldırgan yetkisi dışındaki kaynaklara/işlemlere erişebilir.",
			CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
			CWE:           "CWE-285",
		},
		EN: kbText{
			Preconditions: "An endpoint with missing/insufficient authorization checks and a low-privilege foothold.",
			Impact:        "Privilege escalation, access to other users' data (IDOR), or full authentication bypass.",
			Remediation:   "Enforce server-side object-level authorization; validate session and role on every request; use secure defaults.",
			Description:   "Access control is weakly enforced, letting an attacker reach resources/actions beyond their privilege.",
			CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
			CWE:           "CWE-285",
		},
	},
	"default-credential": {
		Name: "Default / Weak Credentials",
		TR: kbText{
			Preconditions: "Varsayılan veya zayıf kimlik bilgisi kabul eden, ağ üzerinden erişilebilen bir servis.",
			Impact:        "Saldırgan geçerli kimlik bilgisiyle oturum açarak yönetim erişimi elde edebilir ve sistemi ele geçirebilir.",
			Remediation:   "Varsayılan parolaları değiştirin; güçlü parola politikası ve hesap kilitleme uygulayın; mümkünse çok faktörlü kimlik doğrulama ekleyin.",
			Description:   "Servis, varsayılan veya kolay tahmin edilebilir kimlik bilgilerini kabul ederek yetkisiz erişime izin verir.",
			CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			CWE:           "CWE-1392",
		},
		EN: kbText{
			Preconditions: "A network-reachable service accepting default or weak credentials.",
			Impact:        "The attacker logs in with valid credentials to gain administrative access and take over the system.",
			Remediation:   "Change default passwords; enforce a strong password policy and account lockout; add multi-factor authentication where possible.",
			Description:   "The service accepts default or easily guessable credentials, permitting unauthorized access.",
			CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			CWE:           "CWE-1392",
		},
	},
	"info-disclosure": {
		Name: "Information Disclosure",
		TR: kbText{
			Preconditions: "Hassas dosya/dizin, yapılandırma, hata ayrıntısı veya iç bilgilerin yetkisiz erişime açık olması.",
			Impact:        "Açığa çıkan bilgiler (kaynak kodu, kimlik bilgileri, iç yollar, sürümler) daha ileri saldırılar için istihbarat sağlar.",
			Remediation:   "Hassas dosya/dizinlere erişimi kısıtlayın; ayrıntılı hata mesajlarını kapatın; dizin listelemeyi devre dışı bırakın; gereksiz uç noktaları kaldırın.",
			Description:   "Uygulama/sunucu, yetkisiz taraflara hassas bilgi ifşa ederek saldırı yüzeyini genişletir.",
			CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
			CWE:           "CWE-200",
		},
		EN: kbText{
			Preconditions: "Sensitive files/directories, configuration, error detail, or internal data are reachable without authorization.",
			Impact:        "Disclosed information (source code, credentials, internal paths, versions) provides intelligence for further attacks.",
			Remediation:   "Restrict access to sensitive files/directories; disable verbose errors; turn off directory listing; remove unnecessary endpoints.",
			Description:   "The application/server discloses sensitive information to unauthorized parties, widening the attack surface.",
			CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
			CWE:           "CWE-200",
		},
	},
	"cve-generic": {
		Name: "Known Component Vulnerability (CVE)",
		TR: kbText{
			Preconditions: "Bilinen bir güvenlik açığı barındıran sürümdeki bir bileşenin/servisin ağ üzerinden erişilebilir olması.",
			Impact:        "İlgili CVE'nin etkisine göre değişir; bilgi ifşasından uzaktan kod çalıştırma ve tam sistem ele geçirmeye kadar uzanabilir.",
			Remediation:   "Bileşeni satıcının yamalı sürümüne güncelleyin; yama uygulanamıyorsa telafi edici önlemler alın; sürüm envanterini düzenli izleyin.",
			Description:   "Kullanılan bileşen, kamuya açık bir güvenlik açığından (CVE) etkilenen bir sürümde çalışmaktadır.",
			CVSSVector:    "",
			CWE:           "CWE-1035",
		},
		EN: kbText{
			Preconditions: "A component/service running a version affected by a publicly known vulnerability is network-reachable.",
			Impact:        "Varies with the specific CVE; ranges from information disclosure to remote code execution and full system compromise.",
			Remediation:   "Update the component to the vendor's patched version; apply compensating controls if patching is not possible; track a version inventory.",
			Description:   "The component in use runs a version affected by a publicly disclosed vulnerability (CVE).",
			CVSSVector:    "",
			CWE:           "CWE-1035",
		},
	},
	"generic": {
		Name: "Security Finding",
		TR: kbText{
			Preconditions: "Etkilenen varlığa ağ veya uygulama düzeyinde erişim.",
			Impact:        "Bulgunun türüne bağlı olarak gizlilik, bütünlük veya erişilebilirlik olumsuz etkilenebilir.",
			Remediation:   "Bulguyu ilgili güvenlik en iyi uygulamalarına göre giderin; yapılandırmayı sıkılaştırın ve etkiyi doğrulamak için yeniden test edin.",
			Description:   "Tarama, etkilenen varlıkta gözden geçirilmesi gereken bir güvenlik bulgusu tespit etti.",
			CVSSVector:    "",
			CWE:           "",
		},
		EN: kbText{
			Preconditions: "Network or application-level access to the affected asset.",
			Impact:        "Depending on the finding type, confidentiality, integrity, or availability may be adversely affected.",
			Remediation:   "Remediate per the relevant security best practices; harden the configuration and retest to confirm impact.",
			Description:   "The scan identified a security finding on the affected asset that warrants review.",
			CVSSVector:    "",
			CWE:           "",
		},
	},
}

// classMatchers maps ordered keyword sets to a class. First match wins, so more
// specific classes are listed before broader ones.
var classMatchers = []struct {
	class string
	kw    []string
}{
	{"sqli", []string{"sql injection", "sqli", "sql-injection"}},
	{"ssti", []string{"template injection", "ssti"}},
	{"xss", []string{"xss", "cross-site script", "cross site script"}},
	{"open-redirect", []string{"open redirect", "open-redirect"}},
	{"cors", []string{"cors"}},
	{"cache-poisoning", []string{"cache poison", "cache-poison"}},
	{"graphql", []string{"graphql"}},
	{"jwt-weakness", []string{"jwt", "json web token"}},
	{"subdomain-takeover", []string{"takeover", "dangling"}},
	{"kerberoasting", []string{"kerberoast", "spn "}},
	{"asreproast", []string{"asrep", "as-rep", "as rep"}},
	{"weak-tls", []string{"tls", "ssl", "cipher", "certificate", "heartbleed", "poodle", "sweet32", "beast", "rc4"}},
	{"missing-security-header", []string{"security header", "missing header", "hsts", "content-security-policy", "csp", "x-frame", "clickjack", "strict-transport"}},
	{"default-credential", []string{"default credential", "default password", "weak password", "default login", "weak credential"}},
	{"auth-bypass", []string{"auth bypass", "authentication bypass", "authorization", "idor", "access control", "privilege"}},
	{"info-disclosure", []string{"disclosure", "exposed", "directory listing", "index of", "information leak", ".git", "backup file"}},
}

// classMatchersByModule maps a source module to a default class when the title
// didn't match a keyword — captures the module's dominant vuln class.
var classByModule = map[string]string{
	"corsscan":     "cors",
	"sstiscan":     "ssti",
	"openredirect": "open-redirect",
	"cachepoison":  "cache-poisoning",
	"graphqlscan":  "graphql",
	"jwt":          "jwt-weakness",
	"sslscan":      "weak-tls",
	"secheaders":   "missing-security-header",
	"takeover":     "subdomain-takeover",
	"authtest":     "auth-bypass",
	"brutef":       "default-credential",
}

// classifyVuln maps a finding (its module + title, plus whether it carries a
// CVE) to a KB class key. Title keywords win; then the module default; then
// cve-generic when a CVE is present; else generic.
func classifyVuln(module, title string, hasCVE bool) string {
	t := strings.ToLower(title)
	for _, m := range classMatchers {
		for _, kw := range m.kw {
			if strings.Contains(t, kw) {
				return m.class
			}
		}
	}
	if c, ok := classByModule[strings.ToLower(module)]; ok {
		return c
	}
	if hasCVE {
		return "cve-generic"
	}
	return "generic"
}

// kbFor returns the KB entry for a class, falling back to generic.
func kbFor(class string) kbEntry {
	if e, ok := vulnKB[class]; ok {
		return e
	}
	return vulnKB["generic"]
}

// kbTextFor returns the language-appropriate kbText for a class.
func kbTextFor(class, lang string) kbText {
	e := kbFor(class)
	if strings.EqualFold(lang, "en") {
		return e.EN
	}
	return e.TR
}
