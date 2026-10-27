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

// vulnKB maps a class key → bilingual narrative. The Description is a fuller,
// multi-sentence explanation of the vulnerability class, while the other fields
// stay concise. The report joins them with the scanner's concrete data.
var vulnKB = map[string]kbEntry{
	"sqli": {
		Name: "SQL Injection",
		TR: kbText{
			Preconditions: "Hedef uygulamaya ağ erişimi ve kullanıcı girdisinin doğrudan SQL sorgusuna dahil edildiği en az bir parametreye erişim.",
			Impact:        "Saldırgan veritabanını okuyabilir/değiştirebilir, kimlik doğrulamayı atlayabilir, hassas verileri sızdırabilir ve bazı durumlarda işletim sistemi komutları çalıştırarak sunucuyu ele geçirebilir.",
			Remediation:   "Parametreli sorgular (prepared statement) veya ORM kullanın; girdileri tür ve biçim olarak doğrulayın; veritabanı hesabına en az ayrıcalık verin; WAF ile ek katman ekleyin.",
			Description:   "Uygulama, güvenilmeyen kullanıcı girdisini parametre olarak bağlamak yerine doğrudan SQL ifadesine birleştirerek sorguyu oluşturur. Girdi, sorgu yapısından ayrılmadığı için saldırgan kendi SQL söz dizimini enjekte edip sorgunun davranışını değiştirebilir. Bu durum rastgele kayıtların okunmasına veya değiştirilmesine, kimlik doğrulama mantığının atlatılmasına ve kullanıcının erişmemesi gereken tablolardan veri çekilmesine olanak tanır. Dosya veya komut yetenekleri açık olan veritabanı motorlarında ise alttaki sunucuda kod çalıştırmaya kadar tırmanabilir.",
			CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			CWE:           "CWE-89",
		},
		EN: kbText{
			Preconditions: "Network access to the target application and reach to at least one parameter whose value is concatenated into a SQL query.",
			Impact:        "An attacker can read/modify the database, bypass authentication, exfiltrate sensitive data, and in some cases execute OS commands to take over the server.",
			Remediation:   "Use parameterized queries (prepared statements) or an ORM; validate input by type and format; grant the database account least privilege; add a WAF as defense in depth.",
			Description:   "The application builds a SQL query by concatenating untrusted user input directly into the statement instead of binding it as a parameter. Because the input is not separated from the query structure, an attacker can inject their own SQL syntax and change what the query does. This allows reading or modifying arbitrary rows, bypassing authentication logic, and extracting data from tables the user should never reach. On database engines that expose file or command primitives it can escalate to code execution on the underlying host.",
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
			Description:   "Uygulama, kullanıcı denetimli girdiyi bulunduğu bağlama (HTML, JavaScript veya öznitelik) uygun bir çıktı kodlaması uygulamadan sayfaya yazar. Bunun sonucunda tarayıcı, saldırganın girdisini veri olarak değil işaretleme veya betik olarak yorumlar ve zafiyetli sitenin güvenlik bağlamında çalıştırır. Yükün nereye düştüğüne göre bu durum tek bir hazırlanmış istekten yansıyabilir, her ziyaretçide tetiklenecek biçimde saklanabilir veya tamamen tarayıcıda DOM üzerinden gerçekleşebilir. Kurbanın oturumunda çalışan betik, oturum çerezlerini ve token'ları okuyup dışarı sızdırabilir, kurban adına işlem yapabilir, sayfayı kimlik avı için yeniden yazabilir veya kapsamdaki diğer işlevlere geçiş yapabilir.",
			CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
			CWE:           "CWE-79",
		},
		EN: kbText{
			Preconditions: "An application that reflects/stores user input and the ability to lure a victim to the triggering page (reflected) or to persist the payload (stored).",
			Impact:        "Script executes in the victim's browser: session cookies can be stolen, actions performed, page content altered, or phishing staged.",
			Remediation:   "Context-aware output encoding (HTML/JS/URL); enforce a Content-Security-Policy; set HttpOnly on cookies; validate input against an allow-list.",
			Description:   "The application places user-controlled input into an HTML, JavaScript, or attribute context of a page without applying output encoding that matches that context. As a result the browser parses the attacker's input as markup or script rather than as data and runs it in the security context of the vulnerable site. Depending on where the payload lands this can be reflected back from a single crafted request, stored so that it fires for every visitor, or executed entirely in the browser through the DOM. Running in the victim's session the script can read and exfiltrate session cookies and tokens, perform actions as the victim, rewrite the page to stage phishing, or pivot to other in-scope functionality.",
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
			Description:   "Kullanıcı girdisi, Jinja2, Twig, Freemarker veya Velocity gibi bir sunucu tarafı şablon motoruna ulaşır ve düz veri gibi ele alınmak yerine şablon ifadesi olarak değerlendirilir. Şablon ifadeleri metot çağırabildiği ve dil iç yapılarına erişebildiği için saldırgan, basit değerleri yazdırmaktan çalışma zamanı nesnelerini çağırmaya geçebilir. Bu genellikle nesne modeline veya dosya sistemine erişim sağlar ve çoğu motorda doğrudan sunucuda rastgele komut çalıştırmaya yol açar. Dolayısıyla bir görüntüleme hatası değil, çoğunlukla kritik ve tam ele geçirmeyle sonuçlanan bir zafiyettir.",
			CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			CWE:           "CWE-1336",
		},
		EN: kbText{
			Preconditions: "An endpoint that passes user input as an expression into a server-side template engine (Jinja2, Twig, Freemarker, etc.).",
			Impact:        "Code execution on the server via the template engine, typically resulting in full server takeover.",
			Remediation:   "Never pass user input into templates as an expression; use sandboxed/logic-less templates; strictly validate input.",
			Description:   "User input reaches a server-side template engine such as Jinja2, Twig, Freemarker, or Velocity where it is evaluated as a template expression rather than treated as plain data. Because template expressions can call methods and reach language internals, the attacker can move from printing simple values to invoking runtime objects. This typically gives access to the object model or the filesystem and, on most engines, leads directly to arbitrary command execution on the server. It is therefore usually a critical, full-compromise issue rather than a display bug.",
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
			Description:   "Bir uç nokta, HTTP yönlendirmesinin hedefini kullanıcı denetimli bir değerden alır ve bu değeri izin verilen hedefler kümesiyle karşılaştırmadan tarayıcıyı oraya gönderir. Saldırgan, güvenilir alan adı üzerinde kurbanı sessizce kendi denetimindeki bir siteye ileten bir bağlantı hazırlar. Bağlantı meşru ana bilgisayar adıyla başladığı için ham kötü amaçlı bir URL'den çok daha inandırıcıdır ve bu da onu kimlik avı ile yönlendirme üzerinden geçen OAuth kodlarını veya diğer token'ları çalmak için etkili kılar. Saldırının değerini, kullanıcıların gerçek alan adına duyduğu güven oluşturur.",
			CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
			CWE:           "CWE-601",
		},
		EN: kbText{
			Preconditions: "An endpoint that takes its redirect target from a user-controlled parameter and does not validate it.",
			Impact:        "Victims are redirected via the trusted domain to attacker-controlled sites, enabling phishing and session/token leakage.",
			Remediation:   "Constrain redirect targets with a server-side allow-list; reject external absolute URLs; prefer relative paths.",
			Description:   "An endpoint takes the destination of an HTTP redirect from a user-controlled value and sends the browser there without checking it against an allowed set of destinations. An attacker crafts a link on the trusted domain that silently forwards the victim to a site they control. Because the link begins with the legitimate hostname it is far more convincing than a raw malicious URL, which makes it effective for phishing and for stealing OAuth codes or other tokens that pass through the redirect. The trust users place in the real domain is what gives the attack its value.",
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
			Description:   "Sunucunun Çapraz Köken Kaynak Paylaşımı (CORS) politikası fazla gevşektir ve ya isteğin taşıdığı Origin değerini olduğu gibi yansıtır ya da kimlik bilgilerine izin verirken geniş kökenlere açık kalır. Bu durum tarayıcıya, bu tür herhangi bir kökendeki bir sayfanın kurbanın kimlik doğrulanmış oturumuna bağlı yanıtları okuyabileceğini bildirir. Saldırgan, oturum açmış bir kurban ziyaret ettiğinde zafiyetli uygulamaya çapraz köken istekleri gönderen ve profil bilgileri, token veya API yanıtları gibi özel verileri geri okuyan bir sayfa barındırır. Sonuç, tarayıcının normalde uyguladığı aynı köken korumalarını zayıflatan çapraz köken veri sızıntısıdır.",
			CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N",
			CWE:           "CWE-942",
		},
		EN: kbText{
			Preconditions: "A CORS policy that reflects the Origin or is overly permissive, on an endpoint accessed with credentials (cookie/token).",
			Impact:        "An attacker-controlled origin can read sensitive responses as the victim, leading to data leakage.",
			Remediation:   "Pin Access-Control-Allow-Origin to a strict allow-list; never reflect the Origin; never combine '*' with credentials.",
			Description:   "The server's Cross-Origin Resource Sharing policy is too loose, either reflecting whatever Origin the request carries or allowing broad origins while also permitting credentials. This tells the browser that a page on any such origin may read responses tied to the victim's authenticated session. An attacker hosts a page that, when visited by a logged-in victim, issues cross-origin requests to the vulnerable application and reads back private data such as profile details, tokens, or API responses. The result is a cross-origin data leak that undermines the same-origin protections the browser would normally enforce.",
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
			Description:   "Uygulama, tarayıcıya yerleşik korumalarını etkinleştirmesini söyleyen HTTP güvenlik başlıklarını içermeyen yanıtlar döndürür veya bu başlıkları etkisiz kalacak kadar zayıf değerlerle ayarlar. Strict-Transport-Security olmadan bağlantılar düz metne düşürülebilir, Content-Security-Policy olmadan enjekte edilen betikler hiçbir kısıtlamayla karşılaşmaz, X-Content-Type-Options olmadan tarayıcı yanıtları amaçlanmayan bir türe MIME-sniff edebilir ve çerçeveleme denetimleri olmadan sayfa clickjacking için görünmez biçimde yüklenebilir. Bu eksikliklerin hiçbiri tek başına bir istismar değildir, ancak her biri bir savunma katmanını kaldırır ve diğer zayıflıklara ulaşmayı kolaylaştırıp etkisini artırır. Bulgu, tek bir kusurdan çok yanıt yapılandırmasındaki bir sıkılaştırma eksikliğini yansıtır.",
			CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
			CWE:           "CWE-693",
		},
		EN: kbText{
			Preconditions: "HTTP responses missing or weakly configuring security headers (HSTS, CSP, X-Frame-Options, etc.).",
			Impact:        "Enables client-side attacks such as clickjacking, MIME sniffing, mixed content, and transport-security weaknesses.",
			Remediation:   "Add Strict-Transport-Security, Content-Security-Policy, X-Content-Type-Options: nosniff, and framing protection (frame-ancestors/X-Frame-Options).",
			Description:   "The application returns responses without the HTTP security headers that instruct the browser to enable its built-in protections, or sets them with values too weak to be effective. Without Strict-Transport-Security connections can be downgraded to plaintext, without a Content-Security-Policy injected scripts face no restriction, without X-Content-Type-Options the browser may MIME-sniff responses into an unintended type, and without framing controls the page can be loaded invisibly for clickjacking. None of these gaps is an exploit on its own, but each removes a layer of defense and makes other weaknesses easier to reach and more damaging. The finding reflects a hardening deficiency in the response configuration rather than a single flaw.",
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
			Description:   "Servis, aktarım güvenliğini SSLv3 veya TLS 1.0/1.1 gibi eski bir protokol, zayıf ya da export seviyesinde bir şifre takımı veya süresi dolmuş, kendinden imzalı ya da zayıf bir algoritmayla imzalanmış bir sertifika kullanarak müzakere eder. Bunların her biri, bağlantıyı izleyebilen veya araya girebilen bir saldırganın trafiği koruması gereken şifrelemeyi zayıflatmasına ya da kırmasına imkân verir. Pratikte bu, yakalanan oturumların çözülmesi, bağlantının düşürülmesi veya aktarım hâlindeki verinin değiştirilmesi anlamına gelebilir. Böylece kanal üzerinden taşınan kimlik bilgileri, oturum token'ları ve diğer hassas veriler açığa çıkar.",
			CVSSVector:    "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N",
			CWE:           "CWE-326",
		},
		EN: kbText{
			Preconditions: "A TLS service offering a weak protocol (SSLv3/TLS1.0/1.1), weak cipher suite, or invalid/weak certificate, plus a network position to intercept.",
			Impact:        "Man-in-the-middle decryption or tampering of traffic, leaking credentials and session data.",
			Remediation:   "Enable only TLS 1.2+; disable weak cipher suites; use strong keys and a current certificate; enforce HSTS.",
			Description:   "The service negotiates transport security using an outdated protocol such as SSLv3 or TLS 1.0/1.1, a weak or export-grade cipher suite, or a certificate that is expired, self-signed, or signed with a weak algorithm. Each of these lets an attacker who can observe or sit between the connection weaken or break the encryption that is supposed to protect the traffic. In practice this can mean decrypting captured sessions, downgrading the connection, or tampering with data in transit. Credentials, session tokens, and any other sensitive data carried over the channel are then exposed.",
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
			Description:   "Bir alt alan adına ait DNS kaydı, genellikle bir CNAME, kuruluşun artık sahip olmadığı veya serbest bıraktığı bir bulut deposu, barındırma platformu ya da SaaS uç noktası gibi üçüncü taraf bir servise işaret etmeye devam eder. Ad çözümlendiği hâlde arkadaki kaynak sahipsiz olduğundan, saldırgan o kaynağı sağlayıcıda kaydedip kuruluşun kendi alt alan adı altında içerik sunmaya başlayabilir. Oradan inandırıcı kimlik avı sayfaları barındırabilir, üst alan adına kapsamlanmış çerezleri yakalayabilir ve markanın itibarını kötüye kullanabilir. Güvenilir bir adın denetimini bir dış kişiye teslim eden şey, bu sahipsiz (dangling) DNS kaydıdır.",
			CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
			CWE:           "CWE-350",
		},
		EN: kbText{
			Preconditions: "A DNS record (CNAME) pointing to an unclaimed/dangling third-party service that the attacker can register.",
			Impact:        "The attacker takes over the subdomain to host content, enabling phishing, cookie theft, and brand damage.",
			Remediation:   "Remove stale DNS records; enforce DNS cleanup in service-decommission workflows; verify resource ownership.",
			Description:   "A DNS record for a subdomain, usually a CNAME, still points at a third-party service such as a cloud bucket, hosting platform, or SaaS endpoint that the organization no longer owns or has released. Because the name resolves but the backing resource is unclaimed, an attacker can register that resource on the provider and start serving content under the organization's own subdomain. From there they can host convincing phishing pages, capture cookies scoped to the parent domain, and abuse the brand's reputation. The dangling DNS entry is what hands control of a trusted name to an outsider.",
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
			Description:   "Uygulama kullanıcıları JSON Web Token ile doğrular ancak bu token'ları bir saldırganın aşabileceği biçimde doğrular, örneğin 'none' algoritmasını kabul eder, zayıf veya tahmin edilebilir bir sır'a güvenir ya da simetrik ve asimetrik anahtarlar arasında algoritma karışıklığına izin verir. Doğrulama atlatılabildiğinde saldırgan, istediği iddiaları taşıyan bir token üretip sunucuya bunu gerçekmiş gibi kabul ettirebilir. Bu, başka kullanıcıların kimliğine bürünmesine, kendi rolünü veya izinlerini değiştirmesine ve kimlik doğrulamayı tümüyle atlatmasına olanak tanır. Token tek kimlik kanıtı olduğundan, üretilebilir bir token kimlik doğrulama sınırını fiilen ortadan kaldırır.",
			CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
			CWE:           "CWE-347",
		},
		EN: kbText{
			Preconditions: "The application authenticates with JWTs and accepts a weak signature (alg=none, weak secret, algorithm confusion).",
			Impact:        "The attacker forges valid tokens to impersonate users, escalate privileges, and bypass authentication.",
			Remediation:   "Use a strong secret signing key; reject the 'none' algorithm; pin the algorithm server-side; scope and time-limit tokens.",
			Description:   "The application authenticates users with JSON Web Tokens but verifies them in a way an attacker can defeat, for example by accepting the 'none' algorithm, trusting a secret that is weak or guessable, or allowing algorithm confusion between symmetric and asymmetric keys. When verification can be bypassed the attacker can craft a token with any claims they choose and have the server accept it as genuine. This lets them impersonate other users, change their own role or permissions, and bypass authentication outright. Because the token is the sole proof of identity, a forgeable token effectively removes the authentication boundary.",
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
			Description:   "Kimliği doğrulanmış herhangi bir etki alanı kullanıcısı, bir Hizmet Asıl Adı (SPN) bulunan hesap için Kerberos servis bileti (TGS) talep edebilir ve bu biletin bir kısmı servis hesabının parolasından türetilen bir anahtarla şifrelenir. Saldırgan bu biletleri talep edip çevrimdışına alır ve hedefe dokunmadan veya hesap kilitlenmesi tetiklemeden parolayı kendi hızında kaba kuvvet ya da sözlük saldırısıyla kırmaya çalışır. Servis hesapları genellikle uzun ömürlü ve yüksek ayrıcalıklı erişim ile insan tarafından seçilmiş zayıf parolalar taşıdığından değerli hedeflerdir. Ele geçirilen bir parola yanal harekete ve sıklıkla etki alanının ele geçirilmesine giden bir yola imkân verir.",
			CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
			CWE:           "CWE-522",
		},
		EN: kbText{
			Preconditions: "A valid domain account and the existence of service accounts that have SPNs.",
			Impact:        "TGS tickets for service accounts are cracked offline to recover passwords, enabling lateral/vertical movement and domain compromise.",
			Remediation:   "Assign long/random passwords (gMSA) to service accounts; remove unnecessary SPNs; enforce AES encryption; monitor abnormal TGS requests.",
			Description:   "Any authenticated domain user can request a Kerberos service ticket (TGS) for an account that has a Service Principal Name, and part of that ticket is encrypted with a key derived from the service account's password. The attacker requests these tickets and takes them offline, where they can brute-force or dictionary-attack the password at their own pace without touching the target or tripping lockouts. Service accounts often carry long-lived, high-privilege access and weak human-chosen passwords, which makes them valuable targets. A recovered password enables lateral movement and frequently a path toward domain compromise.",
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
			Description:   "Bazı etki alanı hesapları, Kerberos ön kimlik doğrulaması gerektirmeyecek şekilde yapılandırılmıştır ve bu da etki alanı denetleyicisinin, parolayı bildiğini kanıtlamadan talep eden herkese bu hesaplar için bir AS-REP döndürmesi anlamına gelir. Bu AS-REP'in bir kısmı hesabın parolasından türetilen anahtarla şifrelendiğinden, saldırgan onu toplayıp rahatça çevrimdışı kırabilir. Materyali talep etmek için önceden bir dayanak noktası veya geçerli kimlik bilgisi gerekmez, yalnızca etki alanı denetleyicisine erişebilmek ve hesap adlarını bilmek yeterlidir. Kırılan bir parola, saldırganın erişimini genişleten çalışan bir etki alanı kimlik bilgisi sağlar.",
			CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
			CWE:           "CWE-522",
		},
		EN: kbText{
			Preconditions: "Accounts in the domain flagged as 'does not require Kerberos pre-authentication'.",
			Impact:        "AS-REP responses for those accounts are cracked offline to recover passwords, expanding domain access.",
			Remediation:   "Require pre-authentication on all accounts; enforce a strong password policy; audit such accounts regularly.",
			Description:   "Some domain accounts are configured so that Kerberos pre-authentication is not required, which means the domain controller will return an AS-REP for them to anyone who asks, without first proving knowledge of the password. Part of that AS-REP is encrypted with the account's password-derived key, so an attacker can collect it and crack it offline at leisure. No prior foothold or valid credential is needed to request the material, only the ability to reach the domain controller and knowledge of the account names. A cracked password yields a working domain credential that widens the attacker's access.",
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
			Description:   "Uygulamanın önünde bulunan bir önbellek katmanı, yanıtı hâlâ değiştiren ancak belirli istek başlıkları gibi önbellek anahtarına dahil edilmeyen girdileri dışarıda bırakan bir anahtar kullanarak yanıtları saklar. Saldırgan, bu anahtarlanmamış girdilerden biri aracılığıyla yanıtı etkileyen bir istek gönderir ve zararlı sürümün, sonradan normal kullanıcıların eşleşeceği bir anahtar altında saklanmasını sağlar. O önbellek kaydından hizmet alan sonraki her ziyaretçi, enjekte edilmiş betik, zorlanmış bir yönlendirme veya bozuk bir sayfa taşıyabilen saldırgan içeriğini alır. Böylece tek bir zehirleme isteği, kayıt süresi dolana veya temizlenene kadar aynı anda birçok kullanıcıyı etkileyebilir.",
			CVSSVector:    "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:L",
			CWE:           "CWE-444",
		},
		EN: kbText{
			Preconditions: "Cached responses are influenced by inputs not included in the cache key (unkeyed inputs).",
			Impact:        "A poisoned cache serves malicious content/headers to many users, enabling XSS, redirection, and denial of service.",
			Remediation:   "Include all response-affecting inputs in the cache key; do not trust unkeyed headers; tighten cache configuration.",
			Description:   "A caching layer in front of the application stores responses using a cache key that leaves out inputs which still change the response, such as certain request headers. An attacker sends a request that influences the response through one of these unkeyed inputs and gets the harmful version stored under a key that normal users will later match. Every subsequent visitor served from that cache entry then receives the attacker's content, which can carry injected scripts, a forced redirect, or a broken page. A single poisoning request can therefore affect many users at once until the entry expires or is purged.",
			CVSSVector:    "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:L",
			CWE:           "CWE-444",
		},
	},
	"graphql": {
		Name: "GraphQL Misconfiguration",
		TR: kbText{
			Preconditions: "İçe bakış (introspection) açık veya derinlik/karmaşıklık sınırı olmayan bir GraphQL uç noktası.",
			Impact:        "Şema keşfi ile saldırı yüzeyi açığa çıkar; iç içe sorgularla hizmet aksatma ve yetkisiz veri erişimi mümkün olabilir.",
			Remediation:   "Canlı ortamda introspection'ı kapatın; sorgu derinliği/karmaşıklığı ve oran sınırı uygulayın; alan bazında yetkilendirme yapın.",
			Description:   "GraphQL uç noktası güvensiz varsayılanlarla açığa çıkmıştır, tipik olarak içe bakış (introspection) açık bırakılmış ve sorgu derinliği, karmaşıklığı veya oranı için herhangi bir sınır konmamıştır. İçe bakış, saldırgana tüm şemayı vererek her tipi, alanı ve mutasyonu haritalandırır ve böylece saldırı yüzeyinin tamamını bir anda açığa çıkarır. Derinlik ve karmaşıklık sınırlarının yokluğu, tek bir derin iç içe veya özyinelemeli sorgunun orantısız sunucu kaynağı tüketmesine ve hizmet aksamasına yol açmasına imkân verir. Zayıf alan düzeyinde yetkilendirmeyle birleştiğinde bu varsayılanlar, çağıranın sorgulayamaması gereken verilere ulaşmayı da kolaylaştırır.",
			CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L",
			CWE:           "CWE-200",
		},
		EN: kbText{
			Preconditions: "A GraphQL endpoint with introspection enabled or no depth/complexity limits.",
			Impact:        "Schema disclosure exposes the attack surface; nested queries enable denial of service and unauthorized data access.",
			Remediation:   "Disable introspection in production; enforce query depth/complexity and rate limits; apply field-level authorization.",
			Description:   "The GraphQL endpoint is exposed with insecure defaults, typically with introspection left enabled and without limits on query depth, complexity, or rate. Introspection hands an attacker the full schema, mapping out every type, field, and mutation and so revealing the entire attack surface at once. The absence of depth and complexity limits lets a single deeply nested or recursive query consume disproportionate server resources and cause denial of service. Combined with weak field-level authorization these defaults also make it easier to reach data the caller should not be able to query.",
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
			Description:   "Uygulama, bir işlemi yapmaya veya bir nesneye erişmeye kimin yetkili olduğunu sunucu tarafında tutarlı biçimde zorunlu kılmaz ve bunun yerine istemciye ya da atlanabilecek kontrollere güvenir. Düşük ayrıcalıklı bir hesaba sahip, bazen hiç hesabı olmayan bir saldırgan, tanımlayıcıları değiştirerek, istekleri yeniden göndererek veya uç noktaları doğrudan çağırarak başka kullanıcılara ya da yöneticilere ait veri ve işlevlere ulaşabilir. Sık görülen biçimleri arasında başka bir kullanıcının nesnesine tanımlayıcısıyla erişmek (IDOR), yalnızca yöneticiye özel bir işlemi çağırmak ve yalnızca arayüzde korunan bir akışı atlamak yer alır. Temel sorun, yetkilendirme kararının hiç verilmemesi veya yanlış tarafa bırakılmış olmasıdır.",
			CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
			CWE:           "CWE-285",
		},
		EN: kbText{
			Preconditions: "An endpoint with missing/insufficient authorization checks and a low-privilege foothold.",
			Impact:        "Privilege escalation, access to other users' data (IDOR), or full authentication bypass.",
			Remediation:   "Enforce server-side object-level authorization; validate session and role on every request; use secure defaults.",
			Description:   "The application does not consistently enforce, on the server, who is allowed to perform an action or reach an object, relying instead on the client or on checks that can be skipped. An attacker with a low-privilege account, or sometimes none at all, can then manipulate identifiers, replay requests, or call endpoints directly to reach data and functionality meant for other users or for administrators. Common forms include referencing another user's object by its identifier (IDOR), invoking an admin-only operation, and stepping past a flow that was only guarded in the interface. The underlying problem is that the authorization decision is missing or trusted to the wrong side.",
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
			Description:   "Ağ üzerinden erişilebilen bir servis, ürünle birlikte gelen veya admin/admin gibi kolayca tahmin edilebilen, kurulumdan sonra değiştirilmemiş bir satıcı varsayılanı gibi kimlik bilgilerini hâlâ kabul eder. Saldırgan bu iyi bilinen değerlerle yalnızca oturum açar, herhangi bir istismara ihtiyaç duymaz ve kendisini meşru bir kullanıcıdan ayıran pek az iz bırakır. Bu tür hesaplar çoğunlukla yönetici yetkili olduğundan, bu durum sıklıkla servisin ve arkasındaki verinin doğrudan denetimini verir. Zayıflık, yazılımın kendisindeki bir kusurdan değil, dağıtım ve yapılandırmadan kaynaklanır.",
			CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			CWE:           "CWE-1392",
		},
		EN: kbText{
			Preconditions: "A network-reachable service accepting default or weak credentials.",
			Impact:        "The attacker logs in with valid credentials to gain administrative access and take over the system.",
			Remediation:   "Change default passwords; enforce a strong password policy and account lockout; add multi-factor authentication where possible.",
			Description:   "A network-reachable service still accepts credentials that ship with the product or that are trivially guessable, such as admin/admin or a vendor default left unchanged after installation. An attacker simply logs in with these well-known values, needing no exploit and leaving little trace that distinguishes them from a legitimate user. Because such accounts are often administrative, this frequently grants immediate control of the service and the data behind it. The weakness stems from deployment and configuration rather than a flaw in the software itself.",
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
			Description:   "Uygulama veya sunucu, iç kalması gereken bilgileri yetkisiz taraflara ifşa eder, örneğin kaynak kodu, yapılandırma dosyaları, yedek arşivler, yığın izleri, iç yollar veya bileşen sürüm numaraları. Tek bir ifşa kendi başına zararsız görünebilir, ancak bu ayrıntılar bir araya geldiğinde teknoloji yığınını haritalar ve diğer zayıflıkların nerede bulunabileceğini ortaya koyar. Saldırganlar bu istihbaratı, belirlenen sürümlerdeki bilinen zafiyetleri hedeflemek, gizli uç noktaları bulmak ve daha isabetli saldırılar hazırlamak için kullanır. Sorun aşırı ifşadan kaynaklanır ve kendi başına doğrudan bir ele geçirmeye yol açmaktan çok saldırı yüzeyini genişletir.",
			CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
			CWE:           "CWE-200",
		},
		EN: kbText{
			Preconditions: "Sensitive files/directories, configuration, error detail, or internal data are reachable without authorization.",
			Impact:        "Disclosed information (source code, credentials, internal paths, versions) provides intelligence for further attacks.",
			Remediation:   "Restrict access to sensitive files/directories; disable verbose errors; turn off directory listing; remove unnecessary endpoints.",
			Description:   "The application or server exposes information to unauthorized parties that was meant to stay internal, such as source code, configuration files, backup archives, stack traces, internal paths, or component version numbers. On its own a single disclosure may seem harmless, but together these details map the technology stack and reveal where other weaknesses are likely to be found. Attackers use this intelligence to target known vulnerabilities in the identified versions, locate hidden endpoints, and craft more precise attacks. The issue is one of over-exposure and widens the attack surface rather than causing direct compromise by itself.",
			CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
			CWE:           "CWE-200",
		},
	},
	"debug-mode": {
		Name: "Application Debug Mode Enabled",
		TR: kbText{
			Preconditions: "Uygulamanın canlı ortamda hata ayıklama (debug) modu açık şekilde çalışması ve etkilenen uç noktalara/hata sayfalarına ağ erişimi.",
			Impact:        "Ayrıntılı hata ve yığın izleri, iç dosya yolları, yapılandırma değerleri, kaynak kodu parçaları ve sürüm bilgileri ifşa olur; ASP.NET'te uzaktan hata ayıklama açık kalırsa istek manipülasyonu ve tanılama (trace.axd) verisi de erişilebilir hale gelir. Bu bilgiler saldırı yüzeyini genişletir ve sonraki saldırıları kolaylaştırır.",
			Remediation:   "Canlı ortamda hata ayıklama modunu kapatın. ASP.NET için web.config içinde <compilation debug=\"false\"> yapın ve mümkünse machine.config'te <deployment retail=\"true\"/> ile makine genelinde zorlayın; trace.axd'yi kapatın (<trace enabled=\"false\"/>) ve özel (custom) hata sayfaları tanımlayarak ayrıntılı hatayı gizleyin. Diğer çerçevelerde eşdeğerini uygulayın (Django DEBUG=False, Flask/PHP display_errors=Off, Rails production ortamı). Değişiklikten sonra yeniden dağıtıp doğrulayın.",
			Description:   "Uygulama canlı ortamda hata ayıklama modu etkin çalışıyor; bu yapılandırma, ayrıntılı hata mesajlarını ve iç yapılandırma/uygulama detaylarını yetkisiz taraflara ifşa eder.",
			CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
			CWE:           "CWE-11",
		},
		EN: kbText{
			Preconditions: "The application runs with debug mode enabled in production, and its error pages / affected endpoints are reachable over the network.",
			Impact:        "Detailed errors and stack traces, internal file paths, configuration values, source snippets and version info are disclosed; on ASP.NET, leaving remote debugging on also exposes request manipulation and diagnostic (trace.axd) data. This widens the attack surface and eases follow-on attacks.",
			Remediation:   "Disable debug mode in production. For ASP.NET set <compilation debug=\"false\"> in web.config and, where possible, enforce it machine-wide with <deployment retail=\"true\"/> in machine.config; disable trace.axd (<trace enabled=\"false\"/>) and configure custom error pages to hide verbose errors. Apply the equivalent for other stacks (Django DEBUG=False, Flask/PHP display_errors=Off, Rails production). Redeploy and retest afterwards.",
			Description:   "The application runs with debug mode enabled in production; this misconfiguration discloses verbose error messages and internal configuration/application detail to unauthorized parties.",
			CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
			CWE:           "CWE-11",
		},
	},
	"cve-generic": {
		Name: "Known Component Vulnerability (CVE)",
		TR: kbText{
			Preconditions: "Bilinen bir güvenlik açığı barındıran sürümdeki bir bileşenin/servisin ağ üzerinden erişilebilir olması.",
			Impact:        "İlgili CVE'nin etkisine göre değişir; bilgi ifşasından uzaktan kod çalıştırma ve tam sistem ele geçirmeye kadar uzanabilir.",
			Remediation:   "Bileşeni satıcının yamalı sürümüne güncelleyin; yama uygulanamıyorsa telafi edici önlemler alın; sürüm envanterini düzenli izleyin.",
			Description:   "Kullanımdaki bir bileşen, kütüphane veya servis, bir veya daha fazla CVE tanımlayıcısı altında takip edilen, kamuya açıklanmış bir zafiyetten etkilenen bir sürümde çalışmaktadır. Belirli ön koşul ve etki her bir CVE'ye göre değişir ve bilgi ifşasından hizmet aksamasına, uzaktan kod çalıştırmaya ve tam sistem ele geçirmeye kadar uzanır. Kusur kamuya açık olduğundan istismar ayrıntıları ve çoğu zaman çalışan kavram kanıtı (PoC) kodu erişilebilir durumdadır ve bu da yamanmamış bir örneğe saldırmak için gereken eforu azaltır. Maruziyet, bu dağıtıma özgü bir hatadan değil, güncel olmayan bir sürümün çalıştırılmasından kaynaklanır.",
			CVSSVector:    "",
			CWE:           "CWE-1035",
		},
		EN: kbText{
			Preconditions: "A component/service running a version affected by a publicly known vulnerability is network-reachable.",
			Impact:        "Varies with the specific CVE; ranges from information disclosure to remote code execution and full system compromise.",
			Remediation:   "Update the component to the vendor's patched version; apply compensating controls if patching is not possible; track a version inventory.",
			Description:   "A component, library, or service in use is running a version that is affected by a publicly disclosed vulnerability tracked under one or more CVE identifiers. The specific precondition and impact depend on the individual CVE and range from information disclosure through denial of service to remote code execution and full system compromise. Because the flaw is public, exploit details and often working proof-of-concept code are available, which lowers the effort required to attack an unpatched instance. The exposure stems from running an outdated version rather than from a custom mistake in this deployment.",
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
			Description:   "Tarama, etkilenen varlıkta bir analist tarafından gözden geçirilmesi ve doğrulanması gereken, güvenlikle ilgili bir durum işaretledi. Bu durum, bu bilgi tabanının tanımladığı belirli zafiyet sınıflarından birine girmediğinden bulgu genel ifadelerle raporlanır ve ciddiyetini ve gerçek dünyadaki etkisini değerlendirmek için tarama sırasında yakalanan somut kanıt kullanılmalıdır. Bunu doğrulanmış bir istismar olarak değil, geçerliliği sınanacak bir ipucu olarak ele alın. Davranışı doğrulayın, etkilenen varlığın bağlamını değerlendirin ve ilgili güvenlik en iyi uygulamasına göre giderin.",
			CVSSVector:    "",
			CWE:           "",
		},
		EN: kbText{
			Preconditions: "Network or application-level access to the affected asset.",
			Impact:        "Depending on the finding type, confidentiality, integrity, or availability may be adversely affected.",
			Remediation:   "Remediate per the relevant security best practices; harden the configuration and retest to confirm impact.",
			Description:   "The scan flagged a security-relevant condition on the affected asset that should be reviewed and confirmed by an analyst. It did not fall into one of the specific vulnerability classes this knowledge base describes, so the finding is reported in general terms and the concrete evidence captured during the scan should be used to judge its severity and real-world impact. Treat it as a lead to validate rather than a confirmed exploit. Confirm the behaviour, assess the context of the affected asset, and remediate according to the relevant security best practice.",
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
	{"debug-mode", []string{"debug mode", "debugging enabled", "debug enabled", "debug is enabled", "asp.net debug", "aspx debug", "trace.axd", "debug=\"true\"", "debug=true"}},
	{"info-disclosure", []string{"disclosure", "exposed", "directory listing", "index of", "information leak", ".git", "backup file"}},
}

// classMatchersByModule maps a source module to a default class when the title
// didn't match a keyword — captures the module's dominant vuln class.
var classByModule = map[string]string{
	"corsscan":     "cors",
	"sstiscan":     "ssti",
	"openredirect": "open-redirect",
	"cachepoison":  "cache-poisoning",
	"jwt":          "jwt-weakness",
	"sslscan":      "weak-tls",
	"secheaders":   "missing-security-header",
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
