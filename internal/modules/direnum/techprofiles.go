package direnum

// TechProfile defines extensions and wordlists for a technology.
//
// `Wordlists` are generic word lists (one word per line) — the scanner pairs
// each word with every entry in `Extensions` to form request paths.
//
// `LiteralLists` are tech-specific full-path wordlists (e.g. SecLists
// `wordpress.fuzz.txt`, `Aspx-Fuzzing-Wordlist`) where each line is already
// a complete path that includes its extension. The scanner uses these
// entries verbatim — no extension iteration on top — so we don't end up
// requesting things like `wp-login.php.aspx`.
type TechProfile struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Extensions []string `json:"extensions"`
	// Per scan level (index 0=light, 1=normal, 2=aggressive).
	Wordlists    [3][]string
	LiteralLists [3][]string
	ExtraWords   []string

	// BundleKey names the generated, bundled tier list this profile prefers
	// (data/direnum-wordlists/<BundleKey>-t{1,2,3}.txt.gz, built by
	// scripts/build-direnum-wordlists.sh). When a bundled tier file for the
	// chosen level EXISTS, the scanner loads it verbatim (its extensions +
	// permutations are already baked in) and skips this profile's system
	// Wordlists/LiteralLists. When it's absent — a fresh clone that hasn't run
	// the generator — the scanner falls back to the system SecLists paths
	// below, exactly as before. Empty BundleKey = always use system lists
	// (CMS/server profiles whose curated SecLists lists have no bundled tier).
	BundleKey string
}

// AllTechProfiles is the full list the user can select
var AllTechProfiles = []TechProfile{
	{
		ID: "php", Name: "PHP", BundleKey: "php",
		Extensions: []string{".php", ".php5", ".php7", ".phtml", ".phar", ".inc", ".phps"},
		Wordlists: [3][]string{
			{WLCommon},
			{WLCommon, WLRaftMediumWords},
			{WLCommon, WLRaftLargeWords, WLDirMedium},
		},
		ExtraWords: []string{
			"wp-admin", "wp-content", "wp-includes", "wp-login", "wp-config", "xmlrpc",
			"administrator", "admin", "login", "config", "phpinfo", "phpmyadmin",
			"info", "test", "debug", "server-status", "server-info",
			"composer.json", "composer.lock", ".env", ".htaccess", ".htpasswd",
		},
	},
	{
		ID: "asp", Name: "ASP.NET / IIS", BundleKey: "dotnet",
		Extensions: []string{".asp", ".aspx", ".ashx", ".asmx", ".axd", ".cshtml", ".config", ".svc", ".dll", ".pdb"},
		Wordlists: [3][]string{
			{WLCommon},
			{WLCommon, WLRaftMediumWords},
			{WLCommon, WLRaftLargeWords, WLDirMedium},
		},
		// Aspx-Fuzzing-Wordlist + DotNetNuke + Sharepoint full-paths run as-is.
		LiteralLists: [3][]string{
			{},
			{WLAspxFuzz},
			{WLAspxFuzz, WLDotNetNuke, WLSharepoint},
		},
		ExtraWords: []string{
			"web.config", "elmah.axd", "trace.axd", "glimpse.axd",
			"bin", "App_Data", "App_Code", "App_GlobalResources",
			"Telerik.Web.UI.WebResource.axd", "ScriptResource.axd",
			"WebResource.axd", "_vti_bin", "_vti_cnf", "_vti_pvt",
		},
	},
	{
		ID: "java", Name: "Java / Tomcat / Spring", BundleKey: "java",
		Extensions: []string{".jsp", ".jspa", ".jspx", ".do", ".action", ".faces", ".xml", ".properties"},
		Wordlists: [3][]string{
			{WLCommon},
			{WLCommon, WLRaftMediumWords},
			{WLCommon, WLRaftLargeWords, WLDirMedium},
		},
		LiteralLists: [3][]string{
			{WLJavaServlets},
			{WLJavaServlets, WLTomcat},
			{WLJavaServlets, WLTomcat},
		},
		ExtraWords: []string{
			"manager", "host-manager", "status", "jolokia", "actuator",
			"health", "info", "env", "beans", "configprops", "mappings",
			"WEB-INF", "META-INF", "struts", "spring", "swagger-ui",
			"api-docs", "v2/api-docs", "v3/api-docs", "swagger-resources",
			"console", "jmx-console", "web-console", "invoker",
		},
	},
	{
		ID: "python", Name: "Python / Django / Flask", BundleKey: "python",
		Extensions: []string{".py", ".pyc"},
		Wordlists: [3][]string{
			{WLCommon},
			{WLCommon, WLRaftMediumWords},
			{WLCommon, WLRaftLargeWords, WLDirMedium},
		},
		LiteralLists: [3][]string{
			{},
			{WLDjango},
			{WLDjango},
		},
		ExtraWords: []string{
			"admin", "api", "static", "media", "debug", "docs",
			"graphql", "graphiql", "__debug__", "django-admin",
			"settings.py", "requirements.txt", "Procfile", ".env",
			"manage.py", "wsgi.py", "asgi.py", "celery",
		},
	},
	{
		ID: "node", Name: "Node.js / Express", BundleKey: "nodejs",
		Extensions: []string{".js", ".json", ".map"},
		Wordlists: [3][]string{
			{WLCommon},
			{WLCommon, WLRaftMediumWords},
			{WLCommon, WLRaftLargeWords, WLDirMedium},
		},
		ExtraWords: []string{
			"package.json", "package-lock.json", "node_modules", ".env",
			"server.js", "app.js", "index.js", "config.js",
			"api", "graphql", "socket.io", "health", "metrics",
			"swagger.json", "openapi.json", ".npmrc", "Procfile",
		},
	},
	{
		ID: "wordpress", Name: "WordPress",
		Extensions: []string{".php", ".txt", ".html", ".xml"},
		Wordlists: [3][]string{
			{WLCommon},
			{WLCommon, WLRaftMediumWords},
			{WLCommon, WLRaftLargeWords, WLDirMedium},
		},
		// SecLists CMS/wordpress.fuzz.txt + plugin/theme lists carry full
		// paths like "wp-content/plugins/akismet/akismet.php" — no
		// extension iteration on top.
		LiteralLists: [3][]string{
			{WLWordPressFull},
			{WLWordPressFull, WLWPPlugins},
			{WLWordPressFull, WLWPPlugins, WLWPThemes, WLCMSConfig},
		},
		ExtraWords: []string{
			"wp-admin", "wp-content", "wp-includes", "wp-login.php",
			"wp-config.php", "wp-config.php.bak", "wp-config.php.old",
			"xmlrpc.php", "wp-cron.php", "wp-json", "wp-sitemap.xml",
			"readme.html", "license.txt", "wp-content/debug.log",
			"wp-content/uploads", "wp-content/plugins", "wp-content/themes",
			"wp-content/backup-db", "wp-admin/install.php",
		},
	},
	{
		ID: "drupal", Name: "Drupal",
		Extensions: []string{".php", ".module", ".inc", ".info"},
		Wordlists: [3][]string{
			{WLCommon},
			{WLCommon, WLRaftMediumWords},
			{WLCommon, WLRaftLargeWords},
		},
		LiteralLists: [3][]string{
			{WLDrupal},
			{WLDrupal, WLDrupalThemes},
			{WLDrupal, WLDrupalThemes, WLCMSConfig},
		},
		ExtraWords: []string{
			"user/login", "user/register", "user/password",
			"admin/config", "admin/people", "admin/structure",
			"sites/default/settings.php", "sites/default/files",
			"CHANGELOG.txt", "INSTALL.txt", "MAINTAINERS.txt",
			"core/CHANGELOG.txt", "core/install.php",
			"modules", "themes", "profiles", "libraries",
		},
	},
	{
		ID: "joomla", Name: "Joomla",
		Extensions: []string{".php", ".html", ".xml"},
		Wordlists: [3][]string{
			{WLCommon},
			{WLCommon, WLRaftMediumWords},
			{WLCommon, WLRaftLargeWords},
		},
		LiteralLists: [3][]string{
			{WLJoomlaPlug},
			{WLJoomlaPlug, WLJoomlaThemes},
			{WLJoomlaPlug, WLJoomlaThemes, WLCMSConfig},
		},
		ExtraWords: []string{
			"administrator", "components", "modules", "templates",
			"plugins", "language", "media", "images", "cache",
			"configuration.php", "htaccess.txt", "robots.txt.dist",
			"administrator/index.php", "administrator/manifests",
		},
	},
	{
		ID: "coldfusion", Name: "Adobe ColdFusion", BundleKey: "coldfusion",
		Extensions: []string{".cfm", ".cfc", ".cfml"},
		Wordlists: [3][]string{
			{WLCommon},
			{WLCommon, WLRaftMediumWords},
			{WLCommon, WLRaftLargeWords},
		},
		LiteralLists: [3][]string{
			{WLColdFusion},
			{WLColdFusion},
			{WLColdFusion, WLCMSConfig},
		},
		ExtraWords: []string{
			"CFIDE", "CFIDE/administrator", "CFIDE/adminapi",
			"CFIDE/scripts", "cfusion", "Application.cfm",
		},
	},
	{
		ID: "ruby", Name: "Ruby / Rails / Rack", BundleKey: "ruby",
		Extensions: []string{".rb", ".erb", ".ru", ".rhtml", ".rjs", ".cgi"},
		Wordlists: [3][]string{
			{WLCommon},
			{WLCommon, WLRaftMediumWords},
			{WLCommon, WLRaftLargeWords, WLDirMedium},
		},
		LiteralLists: [3][]string{
			{WLRubyOnRails},
			{WLRubyOnRails},
			{WLRubyOnRails, WLDBBackups},
		},
		ExtraWords: []string{
			"config.ru", "Gemfile", "Gemfile.lock", "Rakefile", "config/database.yml",
			"config/secrets.yml", "config/master.key", "config/credentials.yml.enc",
			"config/routes.rb", "db/schema.rb", "db/seeds.rb", ".env", "public",
			"rails/info/routes", "rails/info/properties", "rails/mailers",
			"sidekiq", "resque", "letter_opener", "assets", "storage",
		},
	},
	{
		ID: "perl", Name: "Perl / CGI", BundleKey: "perl",
		Extensions: []string{".pl", ".pm", ".cgi", ".fcgi", ".plx"},
		Wordlists: [3][]string{
			{WLCommon},
			{WLCommon, WLRaftMediumWords},
			{WLCommon, WLRaftLargeWords, WLDirMedium},
		},
		LiteralLists: [3][]string{
			{WLCGIs},
			{WLCGIs, WLCGIXPlatform},
			{WLCGIs, WLCGIXPlatform},
		},
		ExtraWords: []string{
			"cgi-bin", "cgi-bin/test.cgi", "cgi-bin/index.cgi", "cgi-bin/admin.cgi",
			"perl-status", "status", "test.pl", "index.pl", "admin.pl",
			"cgi-sys", "cgi-bin/printenv.pl", "cgi-bin/test-cgi", "cgi-bin/php.cgi",
			"awstats/awstats.pl", "cgi-bin/awstats.pl", "webmin", "mailman",
		},
	},
	{
		ID: "classicasp", Name: "Classic ASP (legacy IIS)", BundleKey: "classicasp",
		Extensions: []string{".asp", ".asa", ".inc", ".cdx", ".cer", ".htr", ".stm", ".shtml"},
		Wordlists: [3][]string{
			{WLCommon},
			{WLCommon, WLRaftMediumWords},
			{WLCommon, WLRaftLargeWords, WLDirMedium},
		},
		LiteralLists: [3][]string{
			{WLIIS},
			{WLIIS, WLFrontpage},
			{WLIIS, WLFrontpage},
		},
		ExtraWords: []string{
			"global.asa", "global.asa.bak", "iisstart.asp", "default.asp", "index.asp",
			"login.asp", "conn.asp", "conn.inc", "db.inc", "database.inc",
			"_vti_bin", "_vti_cnf", "_vti_pvt", "_vti_bin/owssvr.dll", "fpdb",
			"_private", "scripts", "iisadmpwd", "msadc", "adovbs.inc",
		},
	},
	{
		ID: "apache", Name: "Apache (httpd)",
		Extensions: []string{".html", ".htm", ".txt"},
		Wordlists: [3][]string{
			{WLCommon},
			{WLCommon, WLRaftMediumWords},
			{WLCommon, WLRaftLargeWords},
		},
		LiteralLists: [3][]string{
			{WLApache},
			{WLApache},
			{WLApache},
		},
		ExtraWords: []string{
			"server-status", "server-info", ".htaccess", ".htpasswd",
			"manual", "icons", "doc", "docs", "icon",
		},
	},
	{
		ID: "general", Name: "General / Unknown", BundleKey: "general",
		Extensions: []string{".html", ".htm", ".txt", ".xml", ".json", ".bak", ".old", ".log", ".sql", ".zip", ".tar.gz"},
		Wordlists: [3][]string{
			{WLCommon},
			{WLCommon, WLRaftMediumWords, WLCommonDirs},
			{WLCommon, WLRaftLargeWords, WLDirMedium, WLCommonDirs},
		},
		LiteralLists: [3][]string{
			{},
			{WLDBBackups},
			{WLDBBackups},
		},
		ExtraWords: []string{
			"robots.txt", "sitemap.xml", ".git", ".git/config", ".git/HEAD",
			".svn", ".svn/entries", ".env", ".htaccess", ".htpasswd",
			"backup", "db", "database", "dump", "sql", "admin",
			"login", "config", "test", "dev", "staging", "debug",
			"crossdomain.xml", "security.txt", ".well-known",
			"server-status", "server-info", "cpanel", "webmail",
		},
	},
	{
		ID: "api", Name: "REST API / GraphQL",
		Extensions: []string{".json", ".xml", ".yaml", ".yml"},
		Wordlists: [3][]string{
			{WLCommon},
			{WLCommon, WLRaftMediumWords},
			{WLCommon, WLRaftLargeWords, WLDirMedium},
		},
		LiteralLists: [3][]string{
			{WLAPIEndpoints},
			{WLAPIEndpoints},
			{WLAPIEndpoints},
		},
		ExtraWords: []string{
			"api", "v1", "v2", "v3", "graphql", "graphiql",
			"swagger", "swagger-ui", "swagger.json", "openapi.json",
			"api-docs", "docs", "redoc", "health", "healthz",
			"status", "info", "metrics", "version", "ping",
			"auth", "login", "register", "token", "oauth",
			"users", "admin", "config", "settings",
		},
	},
}

// Wordlist paths.
//
// Generic word lists — pairs with extensions in the request builder.
const (
	WLCommon          = "/usr/share/seclists/Discovery/Web-Content/common.txt"
	WLRaftMediumWords = "/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt"
	WLRaftLargeWords  = "/usr/share/seclists/Discovery/Web-Content/raft-large-words.txt"
	WLDirSmall        = "/usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt"
	WLDirMedium       = "/usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt"
	WLCommonDirs      = "/usr/share/seclists/Discovery/Web-Content/common_directories.txt"
)

// Tech-specific full-path lists — used verbatim, no extension iteration.
const (
	WLAspxFuzz      = "/usr/share/seclists/Discovery/Web-Content/Aspx-Fuzzing-Wordlist"
	WLJavaServlets  = "/usr/share/seclists/Discovery/Web-Content/JavaServlets-Common.fuzz.txt"
	WLTomcat        = "/usr/share/seclists/Discovery/Web-Content/tomcat.txt"
	WLApache        = "/usr/share/seclists/Discovery/Web-Content/apache.txt"
	WLAPIEndpoints  = "/usr/share/seclists/Discovery/Web-Content/common-api-endpoints-mazen160.txt"
	WLDBBackups     = "/usr/share/seclists/Discovery/Web-Content/Common-DB-Backups.txt"
	WLWordPressFull = "/usr/share/seclists/Discovery/Web-Content/CMS/wordpress.fuzz.txt"
	WLWPPlugins     = "/usr/share/seclists/Discovery/Web-Content/CMS/wp-plugins.fuzz.txt"
	WLWPThemes      = "/usr/share/seclists/Discovery/Web-Content/CMS/wp-themes.fuzz.txt"
	WLDrupal        = "/usr/share/seclists/Discovery/Web-Content/CMS/Drupal.txt"
	WLDrupalThemes  = "/usr/share/seclists/Discovery/Web-Content/CMS/drupal-themes.fuzz.txt"
	WLJoomlaPlug    = "/usr/share/seclists/Discovery/Web-Content/CMS/joomla-plugins.fuzz.txt"
	WLJoomlaThemes  = "/usr/share/seclists/Discovery/Web-Content/CMS/joomla-themes.fuzz.txt"
	WLDjango        = "/usr/share/seclists/Discovery/Web-Content/CMS/Django.txt"
	WLColdFusion    = "/usr/share/seclists/Discovery/Web-Content/CMS/ColdFusion.fuzz.txt"
	WLDotNetNuke    = "/usr/share/seclists/Discovery/Web-Content/CMS/dotnetnuke.txt"
	WLSharepoint    = "/usr/share/seclists/Discovery/Web-Content/CMS/Sharepoint.txt"
	WLCMSConfig     = "/usr/share/seclists/Discovery/Web-Content/CMS/cms-configuration-files.txt"
	WLRubyOnRails   = "/usr/share/seclists/Discovery/Web-Content/Programming-Language-Specific/ror.txt"
	WLCGIs          = "/usr/share/seclists/Discovery/Web-Content/LEGACY-SERVICES/CGIs/CGIs.txt"
	WLCGIXPlatform  = "/usr/share/seclists/Discovery/Web-Content/LEGACY-SERVICES/CGIs/CGI-XPlatform.fuzz.txt"
	WLIIS           = "/usr/share/seclists/Discovery/Web-Content/Web-Servers/IIS.txt"
	WLFrontpage     = "/usr/share/seclists/Discovery/Web-Content/Microsoft-Frontpage.txt"
)
