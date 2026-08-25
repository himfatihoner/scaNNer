package techdetect

import (
	"fmt"
	"strings"
)

// TechCategory groups technologies
type TechCategory string

const (
	CatCMS       TechCategory = "CMS"
	CatFramework TechCategory = "Framework"
	CatServer    TechCategory = "Web Server"
	CatLanguage  TechCategory = "Language"
	CatJS        TechCategory = "JavaScript"
	CatCDN       TechCategory = "CDN"
	CatAnalytics TechCategory = "Analytics"
	CatSecurity  TechCategory = "Security"
	CatCache     TechCategory = "Caching"
	CatFont      TechCategory = "Font"
	CatUI        TechCategory = "UI Framework"
	CatMisc      TechCategory = "Miscellaneous"
)

// Fingerprint defines a technology detection rule
type Fingerprint struct {
	Name       string
	Category   TechCategory
	Headers    map[string]string // header -> value contains
	Cookies    []string          // cookie name contains
	BodyMatch  []string          // HTML body contains
	MetaMatch  map[string]string // <meta name=X content contains Y>
	ScriptSrc  []string          // <script src contains
	LinkHref   []string          // <link href contains
	HeaderOnly bool              // only check headers, skip body
}

// Fingerprints is the built-in detection database
var Fingerprints = []Fingerprint{
	// --- CMS ---
	{Name: "WordPress", Category: CatCMS, BodyMatch: []string{"/wp-content/", "/wp-includes/", "wp-json"}, MetaMatch: map[string]string{"generator": "wordpress"}},
	{Name: "Joomla", Category: CatCMS, BodyMatch: []string{"/media/jui/", "/components/com_"}, MetaMatch: map[string]string{"generator": "joomla"}},
	{Name: "Drupal", Category: CatCMS, Headers: map[string]string{"X-Generator": "Drupal"}, BodyMatch: []string{"sites/default/files", "drupal.js"}},
	{Name: "Shopify", Category: CatCMS, BodyMatch: []string{"cdn.shopify.com", "Shopify.theme"}, Headers: map[string]string{"X-ShopId": ""}},
	{Name: "Magento", Category: CatCMS, BodyMatch: []string{"skin/frontend/", "Mage.Cookies", "/static/version"}, Cookies: []string{"frontend"}},
	{Name: "Ghost", Category: CatCMS, BodyMatch: []string{"ghost-url"}, MetaMatch: map[string]string{"generator": "ghost"}},
	{Name: "Squarespace", Category: CatCMS, BodyMatch: []string{"squarespace.com", "static.squarespace.com"}},
	{Name: "Wix", Category: CatCMS, BodyMatch: []string{"wix.com", "X-Wix-"}},
	{Name: "Hugo", Category: CatCMS, MetaMatch: map[string]string{"generator": "hugo"}},
	{Name: "Jekyll", Category: CatCMS, MetaMatch: map[string]string{"generator": "jekyll"}},

	// --- Frameworks ---
	{Name: "React", Category: CatFramework, BodyMatch: []string{"data-reactroot", "data-reactid", "react-dom", "_reactrootcontainer"}},
	{Name: "Next.js", Category: CatFramework, BodyMatch: []string{"__NEXT_DATA__", "_next/static"}, Headers: map[string]string{"X-Powered-By": "Next.js"}},
	{Name: "Vue.js", Category: CatFramework, BodyMatch: []string{"vue.js", "vue.min.js", "vue.runtime", "__vue__"}},
	{Name: "Nuxt.js", Category: CatFramework, BodyMatch: []string{"__NUXT__", "_nuxt/"}, Headers: map[string]string{"X-Powered-By": "Nuxt"}},
	{Name: "Angular", Category: CatFramework, BodyMatch: []string{"ng-version", "ng-app", "angular.js", "angular.min.js"}},
	{Name: "Svelte", Category: CatFramework, BodyMatch: []string{"__svelte", "svelte-"}},
	{Name: "Laravel", Category: CatFramework, Cookies: []string{"laravel_session", "XSRF-TOKEN"}, Headers: map[string]string{"X-Powered-By": "Laravel"}},
	// Django: the reliable signal is the CSRF cookie. The old fingerprint also
	// matched Headers{"X-Frame-Options": ""} (present with ANY value) — but
	// X-Frame-Options is a near-universal security header, so EVERY site that
	// sets it was falsely detected as Django. Removed; rely on the csrftoken
	// cookie + Django's CSRF form token in the body.
	{Name: "Django", Category: CatFramework, Cookies: []string{"csrftoken"}, BodyMatch: []string{"csrfmiddlewaretoken"}},
	{Name: "Rails", Category: CatFramework, Headers: map[string]string{"X-Powered-By": "Phusion Passenger"}, Cookies: []string{"_rails_", "_session_id"}},
	{Name: "Express.js", Category: CatFramework, Headers: map[string]string{"X-Powered-By": "Express"}},
	{Name: "ASP.NET", Category: CatFramework, Headers: map[string]string{"X-Powered-By": "ASP.NET", "X-AspNet-Version": ""}, Cookies: []string{"ASP.NET_SessionId"}},
	{Name: "Spring", Category: CatFramework, Cookies: []string{"JSESSIONID"}, Headers: map[string]string{"X-Application-Context": ""}},
	{Name: "Flask", Category: CatFramework, Headers: map[string]string{"Server": "Werkzeug"}},

	// --- Web Servers ---
	{Name: "Nginx", Category: CatServer, Headers: map[string]string{"Server": "nginx"}, HeaderOnly: true},
	{Name: "Apache", Category: CatServer, Headers: map[string]string{"Server": "Apache"}, HeaderOnly: true},
	// Microsoft IIS is defined once, canonically, in the extended server set
	// below (Name "Microsoft IIS"). A second "IIS" entry here matched the same
	// "Server: Microsoft-IIS" header and produced a duplicate, version-less
	// detection that flooded CVE matching with IIS-6.0-only false positives.
	{Name: "LiteSpeed", Category: CatServer, Headers: map[string]string{"Server": "LiteSpeed"}, HeaderOnly: true},
	{Name: "Caddy", Category: CatServer, Headers: map[string]string{"Server": "Caddy"}, HeaderOnly: true},
	{Name: "Tomcat", Category: CatServer, Headers: map[string]string{"Server": "Apache-Coyote"}, HeaderOnly: true},
	{Name: "OpenResty", Category: CatServer, Headers: map[string]string{"Server": "openresty"}, HeaderOnly: true},
	{Name: "Envoy", Category: CatServer, Headers: map[string]string{"Server": "envoy", "X-Envoy-": ""}, HeaderOnly: true},

	// --- Languages ---
	{Name: "PHP", Category: CatLanguage, Headers: map[string]string{"X-Powered-By": "PHP"}, HeaderOnly: true},
	{Name: "Java", Category: CatLanguage, Cookies: []string{"JSESSIONID"}, HeaderOnly: true},
	{Name: "Python", Category: CatLanguage, Headers: map[string]string{"Server": "Python"}, HeaderOnly: true},

	// --- JavaScript Libraries ---
	{Name: "jQuery", Category: CatJS, BodyMatch: []string{"jquery.min.js", "jquery.js", "jquery-"}},
	{Name: "Bootstrap", Category: CatUI, BodyMatch: []string{"bootstrap.min.css", "bootstrap.min.js", "bootstrap.css"}},
	{Name: "Tailwind CSS", Category: CatUI, BodyMatch: []string{"tailwindcss", "tailwind.min.css"}},
	{Name: "Font Awesome", Category: CatFont, BodyMatch: []string{"font-awesome", "fontawesome"}},
	{Name: "Google Fonts", Category: CatFont, BodyMatch: []string{"fonts.googleapis.com", "fonts.gstatic.com"}},

	// --- CDN ---
	{Name: "Cloudflare", Category: CatCDN, Headers: map[string]string{"Cf-Ray": "", "Server": "cloudflare"}, HeaderOnly: true},
	{Name: "AWS CloudFront", Category: CatCDN, Headers: map[string]string{"X-Amz-Cf-Id": "", "Via": "cloudfront"}, HeaderOnly: true},
	{Name: "Fastly", Category: CatCDN, Headers: map[string]string{"X-Served-By": "cache-", "Via": "varnish"}, HeaderOnly: true},
	{Name: "Akamai", Category: CatCDN, Headers: map[string]string{"X-Akamai-Transformed": ""}, HeaderOnly: true},
	{Name: "Vercel", Category: CatCDN, Headers: map[string]string{"X-Vercel-Id": "", "Server": "Vercel"}, HeaderOnly: true},
	{Name: "Netlify", Category: CatCDN, Headers: map[string]string{"X-Nf-Request-Id": "", "Server": "Netlify"}, HeaderOnly: true},

	// --- Analytics ---
	{Name: "Google Analytics", Category: CatAnalytics, BodyMatch: []string{"google-analytics.com/analytics.js", "googletagmanager.com", "gtag/js", "ga.js"}},
	{Name: "Google Tag Manager", Category: CatAnalytics, BodyMatch: []string{"googletagmanager.com/gtm.js"}},
	{Name: "Facebook Pixel", Category: CatAnalytics, BodyMatch: []string{"connect.facebook.net", "fbevents.js", "fbq("}},
	{Name: "Hotjar", Category: CatAnalytics, BodyMatch: []string{"static.hotjar.com", "hotjar.com"}},
	{Name: "Segment", Category: CatAnalytics, BodyMatch: []string{"cdn.segment.com", "segment.io/analytics.js"}},

	// --- Security ---
	{Name: "reCAPTCHA", Category: CatSecurity, BodyMatch: []string{"google.com/recaptcha", "g-recaptcha"}},
	{Name: "hCaptcha", Category: CatSecurity, BodyMatch: []string{"hcaptcha.com", "h-captcha"}},
	{Name: "HSTS", Category: CatSecurity, Headers: map[string]string{"Strict-Transport-Security": ""}, HeaderOnly: true},
	{Name: "CSP", Category: CatSecurity, Headers: map[string]string{"Content-Security-Policy": ""}, HeaderOnly: true},

	// --- Caching ---
	{Name: "Varnish", Category: CatCache, Headers: map[string]string{"Via": "varnish", "X-Varnish": ""}, HeaderOnly: true},
	{Name: "Redis", Category: CatCache, Headers: map[string]string{"X-Cache-Engine": "Redis"}, HeaderOnly: true},

	// ============================================================
	// EXTENDED FINGERPRINT SET — added for broader detection coverage
	// ============================================================

	// --- Additional CMS / SaaS site builders ---
	{Name: "TYPO3", Category: CatCMS, BodyMatch: []string{"typo3conf/", "typo3temp/"}, MetaMatch: map[string]string{"generator": "typo3"}},
	{Name: "MediaWiki", Category: CatCMS, MetaMatch: map[string]string{"generator": "mediawiki"}, BodyMatch: []string{"wgPageName", "/load.php?lang="}},
	{Name: "Bitrix", Category: CatCMS, BodyMatch: []string{"bitrix/templates/", "bitrix/js/"}, Headers: map[string]string{"X-Powered-CMS": "Bitrix"}},
	{Name: "Concrete CMS", Category: CatCMS, BodyMatch: []string{"/concrete/", "ccm-page-controls"}, MetaMatch: map[string]string{"generator": "concrete"}},
	{Name: "DotNetNuke", Category: CatCMS, BodyMatch: []string{"DotNetNuke", "/Portals/_default/"}, Cookies: []string{"DNN_"}},
	{Name: "Sitecore", Category: CatCMS, BodyMatch: []string{"sitecore/shell/", "/sitecore/content/"}, Cookies: []string{"SC_ANALYTICS"}},
	{Name: "Adobe Experience Manager", Category: CatCMS, BodyMatch: []string{"/etc/clientlibs/", "Granite.HTTP", "/content/dam/"}, Headers: map[string]string{"X-AEM-Adobe-Experience-Manager": ""}},
	{Name: "Kentico", Category: CatCMS, BodyMatch: []string{"CMSPages/", "Kentico"}, Cookies: []string{"CMSPreferredCulture"}},
	{Name: "Umbraco", Category: CatCMS, BodyMatch: []string{"/umbraco/", "Umbraco.Web"}, Cookies: []string{"UMB_UCONTEXT"}},
	{Name: "Webflow", Category: CatCMS, BodyMatch: []string{"webflow.com", "data-wf-page", "data-wf-site"}},
	{Name: "Weebly", Category: CatCMS, BodyMatch: []string{"weeblycloud", "weebly.com"}},
	{Name: "Strapi", Category: CatCMS, Headers: map[string]string{"X-Powered-By": "Strapi"}, BodyMatch: []string{"/uploads/strapi"}},
	{Name: "Contentful", Category: CatCMS, BodyMatch: []string{"images.ctfassets.net", "ctfassets.net"}},
	{Name: "Sanity", Category: CatCMS, BodyMatch: []string{"cdn.sanity.io"}},
	{Name: "Storyblok", Category: CatCMS, BodyMatch: []string{"a.storyblok.com"}},
	{Name: "PrestaShop", Category: CatCMS, BodyMatch: []string{"prestashop", "/themes/classic/"}, Cookies: []string{"PrestaShop-"}, MetaMatch: map[string]string{"generator": "prestashop"}},
	{Name: "OpenCart", Category: CatCMS, BodyMatch: []string{"catalog/view/theme/", "/index.php?route="}, Cookies: []string{"OCSESSID"}},
	{Name: "BigCommerce", Category: CatCMS, BodyMatch: []string{"cdn11.bigcommerce.com", "bigcommerce.com"}},
	{Name: "Salesforce Commerce", Category: CatCMS, BodyMatch: []string{"demandware.net", "/dwsharedstore/"}},
	{Name: "Hybris", Category: CatCMS, BodyMatch: []string{"_s/wcsstore/", "hybris/"}},

	// --- Additional Frameworks (web app) ---
	{Name: "Remix", Category: CatFramework, BodyMatch: []string{"__remixContext", "remix-run"}},
	{Name: "Astro", Category: CatFramework, BodyMatch: []string{"data-astro-cid", "astro-island"}},
	{Name: "SvelteKit", Category: CatFramework, BodyMatch: []string{"__sveltekit_", "data-sveltekit"}},
	{Name: "Gatsby", Category: CatFramework, BodyMatch: []string{"___gatsby", "gatsby-image", "gatsby-link"}, MetaMatch: map[string]string{"generator": "gatsby"}},
	{Name: "Hugo", Category: CatFramework, MetaMatch: map[string]string{"generator": "hugo"}},
	{Name: "Eleventy", Category: CatFramework, MetaMatch: map[string]string{"generator": "eleventy"}},
	{Name: "Hexo", Category: CatFramework, MetaMatch: map[string]string{"generator": "hexo"}},
	{Name: "Vite", Category: CatFramework, BodyMatch: []string{"/@vite/client", "/@id/__vite-browser-external"}},
	{Name: "Webpack", Category: CatFramework, BodyMatch: []string{"webpackJsonp", "__webpack_require__", "__webpack_modules__"}},
	{Name: "Parcel", Category: CatFramework, BodyMatch: []string{"parcelRequire"}},
	{Name: "Turbo", Category: CatFramework, BodyMatch: []string{"data-turbo", "turbo-frame", "turbo-stream"}},
	{Name: "Stimulus", Category: CatFramework, BodyMatch: []string{"data-controller", "stimulus.js"}},
	{Name: "HTMX", Category: CatFramework, BodyMatch: []string{"htmx.org", "hx-get", "hx-post", "data-hx-"}},
	{Name: "Alpine.js", Category: CatFramework, BodyMatch: []string{"alpinejs", "x-data=", "x-init", "x-show=", "x-bind"}},
	{Name: "Lit", Category: CatFramework, BodyMatch: []string{"lit-element", "lit-html", "lit/dist"}},
	{Name: "Stencil", Category: CatFramework, BodyMatch: []string{"stencil-runtime", "data-stencil"}},
	{Name: "Ember.js", Category: CatFramework, BodyMatch: []string{"ember-application", "ember-cli", "ember.js"}, MetaMatch: map[string]string{"name": "ember-cli"}},
	{Name: "Backbone.js", Category: CatFramework, BodyMatch: []string{"backbone.js", "backbone.min.js"}},
	{Name: "Knockout.js", Category: CatFramework, BodyMatch: []string{"knockout.js", "knockout-", "data-bind="}},
	{Name: "Meteor", Category: CatFramework, BodyMatch: []string{"meteor.js", "meteor-deps"}},
	{Name: "Symfony", Category: CatFramework, Headers: map[string]string{"X-Powered-By": "Symfony", "X-Debug-Token": ""}, Cookies: []string{"PHPSESSID"}, BodyMatch: []string{"sf-toolbar", "_profiler/"}},
	{Name: "CodeIgniter", Category: CatFramework, Cookies: []string{"ci_session"}},
	{Name: "CakePHP", Category: CatFramework, Cookies: []string{"CAKEPHP"}},
	{Name: "Yii", Category: CatFramework, Cookies: []string{"YII_CSRF_TOKEN", "PHPSESSID"}, BodyMatch: []string{"/assets/yii"}},
	{Name: "Phoenix", Category: CatFramework, Cookies: []string{"_phoenix_key"}, Headers: map[string]string{"X-Phoenix": ""}},
	{Name: "Sails.js", Category: CatFramework, Headers: map[string]string{"X-Powered-By": "Sails"}},
	{Name: "Hapi", Category: CatFramework, Headers: map[string]string{"X-Powered-By": "Hapi"}},
	{Name: "Koa", Category: CatFramework, Headers: map[string]string{"X-Powered-By": "Koa"}},
	{Name: "FastAPI", Category: CatFramework, Headers: map[string]string{"server": "uvicorn"}, BodyMatch: []string{"/docs#operation", "/openapi.json", "swagger-ui"}},
	{Name: "Flask", Category: CatFramework, Headers: map[string]string{"server": "Werkzeug"}, Cookies: []string{"session"}},
	{Name: "Tornado", Category: CatFramework, Headers: map[string]string{"server": "TornadoServer"}},
	{Name: "Spring", Category: CatFramework, Headers: map[string]string{"X-Application-Context": ""}, Cookies: []string{"JSESSIONID"}, BodyMatch: []string{"spring-boot"}},
	{Name: "Struts", Category: CatFramework, BodyMatch: []string{"struts/dojo", "/struts/"}},
	{Name: "ASP.NET", Category: CatFramework, Headers: map[string]string{"X-AspNet-Version": "", "X-AspNetMvc-Version": ""}, Cookies: []string{"ASP.NET_SessionId"}, BodyMatch: []string{"__VIEWSTATE", "__EVENTTARGET"}},
	// ASP.NET Core is signalled ONLY by the ".AspNetCore" cookie. The
	// "X-Powered-By: ASP.NET" header is the CLASSIC ASP.NET signal (handled by
	// the "ASP.NET" fingerprint) — keying Core off it mis-tagged every classic
	// ASP.NET box as Core.
	{Name: "ASP.NET Core", Category: CatFramework, Cookies: []string{".AspNetCore."}},
	{Name: "Blazor", Category: CatFramework, BodyMatch: []string{"_framework/blazor", "blazor.webassembly.js"}},
	{Name: "Adonis.js", Category: CatFramework, Cookies: []string{"adonis-session"}},
	{Name: "NestJS", Category: CatFramework, Headers: map[string]string{"X-Powered-By": "NestJS"}},

	// --- Additional Web servers / proxies ---
	{Name: "Apache HTTPD", Category: CatServer, Headers: map[string]string{"server": "Apache"}, HeaderOnly: true},
	{Name: "nginx", Category: CatServer, Headers: map[string]string{"server": "nginx"}, HeaderOnly: true},
	{Name: "Microsoft IIS", Category: CatServer, Headers: map[string]string{"server": "Microsoft-IIS"}, HeaderOnly: true},
	{Name: "LiteSpeed", Category: CatServer, Headers: map[string]string{"server": "LiteSpeed", "X-LiteSpeed-Cache": ""}, HeaderOnly: true},
	{Name: "OpenResty", Category: CatServer, Headers: map[string]string{"server": "openresty"}, HeaderOnly: true},
	{Name: "Caddy", Category: CatServer, Headers: map[string]string{"server": "Caddy"}, HeaderOnly: true},
	{Name: "Tomcat", Category: CatServer, Headers: map[string]string{"server": "Apache-Coyote", "X-Powered-By": "JSP"}},
	{Name: "Jetty", Category: CatServer, Headers: map[string]string{"server": "Jetty"}, HeaderOnly: true},
	{Name: "WildFly", Category: CatServer, Headers: map[string]string{"server": "WildFly", "X-Powered-By": "Undertow"}, HeaderOnly: true},
	{Name: "Cherokee", Category: CatServer, Headers: map[string]string{"server": "Cherokee"}, HeaderOnly: true},
	{Name: "Lighttpd", Category: CatServer, Headers: map[string]string{"server": "lighttpd"}, HeaderOnly: true},
	{Name: "Gunicorn", Category: CatServer, Headers: map[string]string{"server": "gunicorn"}, HeaderOnly: true},
	{Name: "uWSGI", Category: CatServer, Headers: map[string]string{"server": "uWSGI"}, HeaderOnly: true},
	{Name: "Puma", Category: CatServer, Headers: map[string]string{"server": "Puma"}, HeaderOnly: true},
	{Name: "Unicorn", Category: CatServer, Headers: map[string]string{"server": "Unicorn"}, HeaderOnly: true},
	{Name: "Phusion Passenger", Category: CatServer, Headers: map[string]string{"server": "Phusion Passenger"}, HeaderOnly: true},

	// --- Additional CDN / Edge ---
	{Name: "Cloudflare", Category: CatCDN, Headers: map[string]string{"server": "cloudflare", "CF-Ray": ""}, HeaderOnly: true},
	{Name: "Cloudflare Pages", Category: CatCDN, Headers: map[string]string{"CF-Pages": ""}, HeaderOnly: true},
	{Name: "Akamai", Category: CatCDN, Headers: map[string]string{"server": "AkamaiGHost", "X-Akamai-Transformed": ""}, HeaderOnly: true},
	{Name: "Fastly", Category: CatCDN, Headers: map[string]string{"X-Served-By": "cache-", "X-Fastly-Request-ID": ""}, HeaderOnly: true},
	{Name: "AWS CloudFront", Category: CatCDN, Headers: map[string]string{"server": "CloudFront", "X-Amz-Cf-Id": ""}, HeaderOnly: true},
	{Name: "Vercel", Category: CatCDN, Headers: map[string]string{"server": "Vercel", "X-Vercel-Id": ""}, HeaderOnly: true},
	{Name: "Netlify", Category: CatCDN, Headers: map[string]string{"server": "Netlify", "X-Nf-Request-Id": ""}, HeaderOnly: true},
	{Name: "GitHub Pages", Category: CatCDN, Headers: map[string]string{"server": "GitHub.com"}, HeaderOnly: true},
	{Name: "GitLab Pages", Category: CatCDN, Headers: map[string]string{"server": "GitLab Pages"}, HeaderOnly: true},
	{Name: "Bunny CDN", Category: CatCDN, Headers: map[string]string{"server": "BunnyCDN"}, HeaderOnly: true},
	{Name: "Sucuri", Category: CatCDN, Headers: map[string]string{"server": "Sucuri", "X-Sucuri-ID": ""}, HeaderOnly: true},
	{Name: "Imperva Incapsula", Category: CatCDN, Headers: map[string]string{"X-Iinfo": "", "X-Cdn": "Incapsula"}, Cookies: []string{"incap_ses_", "visid_incap_"}},
	{Name: "KeyCDN", Category: CatCDN, Headers: map[string]string{"server": "keycdn-engine"}, HeaderOnly: true},
	{Name: "StackPath", Category: CatCDN, Headers: map[string]string{"server": "StackPath"}, HeaderOnly: true},
	{Name: "Azure CDN", Category: CatCDN, Headers: map[string]string{"X-Azure-Ref": ""}, HeaderOnly: true},
	{Name: "Google Cloud CDN", Category: CatCDN, Headers: map[string]string{"server": "Google Frontend", "Via": "1.1 google"}, HeaderOnly: true},

	// --- WAF / Security ---
	{Name: "Cloudflare WAF", Category: CatSecurity, Cookies: []string{"__cf_bm", "__cfduid"}, Headers: map[string]string{"CF-Mitigated": ""}},
	{Name: "AWS WAF", Category: CatSecurity, Headers: map[string]string{"X-Amzn-RequestId": ""}, Cookies: []string{"aws-waf-token"}},
	{Name: "F5 BIG-IP", Category: CatSecurity, Cookies: []string{"BIGipServer", "TS01", "F5_ST"}, Headers: map[string]string{"server": "BIG-IP"}},
	{Name: "Barracuda WAF", Category: CatSecurity, Cookies: []string{"barra_counter_session"}, Headers: map[string]string{"server": "Barracuda"}},
	{Name: "Citrix NetScaler", Category: CatSecurity, Cookies: []string{"NSC_", "citrix_ns_id"}, Headers: map[string]string{"Via": "NS-CACHE"}},
	{Name: "FortiWeb", Category: CatSecurity, Cookies: []string{"FORTIWAFSID"}, Headers: map[string]string{"X-FW-Server": ""}},
	{Name: "ModSecurity", Category: CatSecurity, Headers: map[string]string{"server": "Mod_Security", "X-Mod-Security": ""}},
	{Name: "Akamai Bot Manager", Category: CatSecurity, Cookies: []string{"_abck", "bm_sz"}, HeaderOnly: false},
	{Name: "PerimeterX", Category: CatSecurity, Cookies: []string{"_px", "_pxhd"}, BodyMatch: []string{"client.perimeterx.net"}},
	{Name: "DataDome", Category: CatSecurity, Cookies: []string{"datadome"}, BodyMatch: []string{"datadome.co"}},
	{Name: "Wordfence", Category: CatSecurity, Cookies: []string{"wordfence_verifiedHuman", "wfvt_"}, Headers: map[string]string{"server": "wordfence"}},
	{Name: "Comodo cWatch", Category: CatSecurity, Headers: map[string]string{"server": "Protected by COMODO"}},

	// --- JavaScript libs / UI frameworks ---
	{Name: "jQuery", Category: CatJS, BodyMatch: []string{"jquery.min.js", "jquery-", "/jquery."}, ScriptSrc: []string{"jquery"}},
	{Name: "jQuery UI", Category: CatJS, BodyMatch: []string{"jquery-ui", "jquery.ui."}},
	{Name: "Lodash", Category: CatJS, BodyMatch: []string{"lodash.min.js", "lodash."}},
	{Name: "Underscore.js", Category: CatJS, BodyMatch: []string{"underscore.js", "underscore.min.js"}},
	{Name: "Modernizr", Category: CatJS, BodyMatch: []string{"modernizr.js", "modernizr-"}},
	{Name: "Moment.js", Category: CatJS, BodyMatch: []string{"moment.js", "moment.min.js"}},
	{Name: "Day.js", Category: CatJS, BodyMatch: []string{"dayjs.min.js", "dayjs/"}},
	{Name: "D3.js", Category: CatJS, BodyMatch: []string{"d3.min.js", "d3.v"}},
	{Name: "Chart.js", Category: CatJS, BodyMatch: []string{"chart.js", "chart.min.js"}},
	{Name: "Three.js", Category: CatJS, BodyMatch: []string{"three.min.js", "three.js"}},
	{Name: "Highcharts", Category: CatJS, BodyMatch: []string{"highcharts.js", "highcharts.com"}},
	{Name: "MathJax", Category: CatJS, BodyMatch: []string{"mathjax.org", "MathJax.js"}},
	{Name: "Prism.js", Category: CatJS, BodyMatch: []string{"prism.js", "prism.min.js", "prismjs"}},
	{Name: "Highlight.js", Category: CatJS, BodyMatch: []string{"highlight.js", "highlight.min.js"}},
	{Name: "Swiper", Category: CatJS, BodyMatch: []string{"swiper.min.js", "swiper-bundle"}},
	{Name: "Slick", Category: CatJS, BodyMatch: []string{"slick.min.js", "slick-carousel"}},
	{Name: "Owl Carousel", Category: CatJS, BodyMatch: []string{"owl.carousel"}},
	{Name: "AOS", Category: CatJS, BodyMatch: []string{"aos.js", "aos.css", "data-aos="}},
	{Name: "GSAP", Category: CatJS, BodyMatch: []string{"gsap.min.js", "gsap/dist", "TweenMax", "TweenLite"}},
	{Name: "Anime.js", Category: CatJS, BodyMatch: []string{"anime.min.js"}},
	{Name: "Mustache.js", Category: CatJS, BodyMatch: []string{"mustache.min.js", "mustache.js"}},
	{Name: "Handlebars", Category: CatJS, BodyMatch: []string{"handlebars.min.js", "handlebars-"}},
	{Name: "RequireJS", Category: CatJS, BodyMatch: []string{"require.js", "requirejs"}},
	{Name: "Polyfill.io", Category: CatJS, BodyMatch: []string{"polyfill.io"}},
	{Name: "Workbox", Category: CatJS, BodyMatch: []string{"workbox-sw.js", "workbox/"}},

	// --- UI Frameworks / CSS ---
	{Name: "Bootstrap", Category: CatUI, BodyMatch: []string{"bootstrap.min.css", "bootstrap.css", "bootstrap.bundle.js", "bootstrap-"}, LinkHref: []string{"bootstrap"}},
	{Name: "Tailwind CSS", Category: CatUI, BodyMatch: []string{"tailwindcss", "/tailwind.min.css"}, ScriptSrc: []string{"cdn.tailwindcss.com"}},
	{Name: "Bulma", Category: CatUI, BodyMatch: []string{"bulma.min.css", "bulma.io"}},
	{Name: "Foundation", Category: CatUI, BodyMatch: []string{"foundation.min.css", "foundation.js"}},
	{Name: "Materialize", Category: CatUI, BodyMatch: []string{"materialize.min.css", "materialize.js"}},
	{Name: "Material UI", Category: CatUI, BodyMatch: []string{"@mui/", "MuiButton", "data-mui-"}},
	{Name: "Material Design Lite", Category: CatUI, BodyMatch: []string{"material.min.css", "getmdl.io"}},
	{Name: "Ant Design", Category: CatUI, BodyMatch: []string{"ant-design", "antd-mobile", "ant-btn"}},
	{Name: "Chakra UI", Category: CatUI, BodyMatch: []string{"chakra-ui", "data-chakra-"}},
	{Name: "Semantic UI", Category: CatUI, BodyMatch: []string{"semantic.min.css", "semantic.min.js"}},
	{Name: "UIKit", Category: CatUI, BodyMatch: []string{"uikit.min.css", "uikit-icons"}},
	{Name: "Vuetify", Category: CatUI, BodyMatch: []string{"vuetify.min.css", "v-application", "vuetify"}},
	{Name: "PrimeFaces", Category: CatUI, BodyMatch: []string{"primefaces.js", "primefaces/"}},
	{Name: "Sencha Ext JS", Category: CatUI, BodyMatch: []string{"ext-all", "Ext.application"}},

	// --- Languages (clarified) ---
	{Name: "PHP", Category: CatLanguage, Headers: map[string]string{"X-Powered-By": "PHP", "server": "PHP"}, Cookies: []string{"PHPSESSID"}},
	{Name: "Python", Category: CatLanguage, Headers: map[string]string{"X-Powered-By": "Python", "server": "Python"}},
	{Name: "Node.js", Category: CatLanguage, Headers: map[string]string{"X-Powered-By": "Node"}},
	{Name: "Ruby", Category: CatLanguage, Headers: map[string]string{"X-Powered-By": "Ruby"}, Cookies: []string{"_session_id"}},
	{Name: "Go", Category: CatLanguage, Headers: map[string]string{"X-Powered-By": "Go"}},
	{Name: "Java", Category: CatLanguage, Cookies: []string{"JSESSIONID"}, Headers: map[string]string{"X-Powered-By": "Servlet", "server": "Tomcat"}},

	// --- Analytics / Tag managers (additional) ---
	{Name: "Google Analytics 4", Category: CatAnalytics, BodyMatch: []string{"googletagmanager.com/gtag/js?id=g-", "gtag('config', 'g-", "gtag(\"config\", \"g-"}},
	{Name: "Mixpanel", Category: CatAnalytics, BodyMatch: []string{"mixpanel.com", "mixpanel-"}},
	{Name: "Amplitude", Category: CatAnalytics, BodyMatch: []string{"amplitude.com", "amplitude.js"}},
	{Name: "Heap", Category: CatAnalytics, BodyMatch: []string{"heap.io", "heapanalytics.com"}},
	{Name: "Fathom", Category: CatAnalytics, BodyMatch: []string{"cdn.usefathom.com", "fathom.js"}},
	{Name: "Plausible", Category: CatAnalytics, BodyMatch: []string{"plausible.io/js", "data-domain="}},
	{Name: "Matomo", Category: CatAnalytics, BodyMatch: []string{"matomo.js", "_paq.push"}},
	{Name: "Hotjar", Category: CatAnalytics, BodyMatch: []string{"static.hotjar.com", "hotjar-"}},
	{Name: "FullStory", Category: CatAnalytics, BodyMatch: []string{"fullstory.com", "_fs_namespace"}},
	{Name: "Intercom", Category: CatAnalytics, BodyMatch: []string{"intercom.io", "intercom-"}},
	{Name: "Drift", Category: CatAnalytics, BodyMatch: []string{"drift.com", "driftt.com"}},
	{Name: "Crisp", Category: CatAnalytics, BodyMatch: []string{"crisp.chat", "crisp-client"}},
	{Name: "Tawk.to", Category: CatAnalytics, BodyMatch: []string{"embed.tawk.to"}},
	{Name: "LiveChat", Category: CatAnalytics, BodyMatch: []string{"cdn.livechatinc.com"}},
	{Name: "Sentry", Category: CatAnalytics, BodyMatch: []string{"sentry-cdn.com", "sentry.io"}},
	{Name: "LogRocket", Category: CatAnalytics, BodyMatch: []string{"cdn.logrocket.io", "logrocket.com"}},
	{Name: "New Relic", Category: CatAnalytics, BodyMatch: []string{"NREUM", "newrelic.com"}},
	{Name: "DataDog RUM", Category: CatAnalytics, BodyMatch: []string{"www.datadoghq-browser-agent.com"}},
	{Name: "Optimizely", Category: CatAnalytics, BodyMatch: []string{"cdn.optimizely.com"}},

	// --- Caching / databases ---
	{Name: "Memcached", Category: CatCache, Headers: map[string]string{"X-Cache-Engine": "Memcached"}, HeaderOnly: true},
	{Name: "Squid", Category: CatCache, Headers: map[string]string{"X-Cache": "HIT from", "Via": "squid"}, HeaderOnly: true},
	{Name: "Cloudflare Cache", Category: CatCache, Headers: map[string]string{"CF-Cache-Status": ""}, HeaderOnly: true},
	{Name: "WP Super Cache", Category: CatCache, Headers: map[string]string{"X-Cache": "supercache"}, HeaderOnly: true},
	{Name: "WP Rocket", Category: CatCache, Headers: map[string]string{"X-Powered-By": "WP Rocket"}, BodyMatch: []string{"wp-rocket"}},
	{Name: "W3 Total Cache", Category: CatCache, Headers: map[string]string{"X-Powered-By": "W3 Total Cache"}, BodyMatch: []string{"W3 Total Cache"}},
	{Name: "LiteSpeed Cache", Category: CatCache, Headers: map[string]string{"X-LiteSpeed-Cache": ""}, HeaderOnly: true},

	// --- Fonts ---
	{Name: "Google Fonts", Category: CatFont, BodyMatch: []string{"fonts.googleapis.com", "fonts.gstatic.com"}, LinkHref: []string{"fonts.googleapis.com"}},
	{Name: "Adobe Fonts (Typekit)", Category: CatFont, BodyMatch: []string{"use.typekit.net", "p.typekit.net"}, LinkHref: []string{"typekit"}},
	{Name: "Font Awesome", Category: CatFont, BodyMatch: []string{"fontawesome", "font-awesome.css"}, LinkHref: []string{"fontawesome"}},
	{Name: "Bootstrap Icons", Category: CatFont, BodyMatch: []string{"bootstrap-icons.css", "bootstrap-icons.woff"}},
	{Name: "Material Icons", Category: CatFont, BodyMatch: []string{"material-icons", "fonts/material"}},
	{Name: "Ionicons", Category: CatFont, BodyMatch: []string{"ionicons.com", "ionicons.min.css"}},

	// --- Misc / E-commerce / Payment ---
	{Name: "Stripe", Category: CatMisc, BodyMatch: []string{"js.stripe.com", "stripe.com/v3"}},
	{Name: "PayPal", Category: CatMisc, BodyMatch: []string{"paypal.com/sdk", "paypal-button-"}},
	{Name: "Square", Category: CatMisc, BodyMatch: []string{"squareup.com", "square.js"}},
	{Name: "Klarna", Category: CatMisc, BodyMatch: []string{"klarna.com", "klarna-checkout"}},
	{Name: "Disqus", Category: CatMisc, BodyMatch: []string{"disqus.com/embed", "disqus_thread"}},
	{Name: "Mailchimp", Category: CatMisc, BodyMatch: []string{"chimpstatic.com", "mailchimp.com"}},
	{Name: "HubSpot", Category: CatMisc, BodyMatch: []string{"js.hs-scripts.com", "_hsq", "hubspot"}},
	{Name: "Salesforce Lightning", Category: CatMisc, BodyMatch: []string{"force.com", "lightning/"}},
	{Name: "Zendesk", Category: CatMisc, BodyMatch: []string{"zendesk.com/embeddable", "zopim.com"}},
	{Name: "Algolia", Category: CatMisc, BodyMatch: []string{"algolia.net", "algoliasearch"}},
	{Name: "Elasticsearch", Category: CatMisc, BodyMatch: []string{"elasticsearch", "/_search?"}},
	{Name: "AWS S3", Category: CatMisc, BodyMatch: []string{".s3.amazonaws.com", "s3-website-"}},
	{Name: "Firebase", Category: CatMisc, BodyMatch: []string{"firebaseapp.com", "firebase-config", "firebaseio.com"}},
	{Name: "Auth0", Category: CatMisc, BodyMatch: []string{"auth0.com", "auth0-spa-js"}},
	{Name: "Okta", Category: CatMisc, BodyMatch: []string{"okta.com", "okta-signin-widget"}},
	{Name: "Recurly", Category: CatMisc, BodyMatch: []string{"recurly.com"}},
	{Name: "Trustpilot", Category: CatMisc, BodyMatch: []string{"trustpilot.com/widget"}},
	{Name: "OneTrust", Category: CatMisc, BodyMatch: []string{"onetrust.com", "OneTrustWPCCPA"}, ScriptSrc: []string{"onetrust"}},
	{Name: "Cookiebot", Category: CatMisc, BodyMatch: []string{"cookiebot.com"}},
	{Name: "Yoast SEO", Category: CatMisc, BodyMatch: []string{"yoast", "Yoast SEO"}, MetaMatch: map[string]string{"generator": "yoast"}},
	{Name: "RankMath", Category: CatMisc, MetaMatch: map[string]string{"generator": "rank math"}},
	{Name: "WooCommerce", Category: CatMisc, BodyMatch: []string{"woocommerce", "wc-blocks-style", "/wp-content/plugins/woocommerce/"}, MetaMatch: map[string]string{"generator": "woocommerce"}},
	{Name: "Elementor", Category: CatMisc, BodyMatch: []string{"elementor-", "/wp-content/plugins/elementor/"}, MetaMatch: map[string]string{"generator": "elementor"}},
	{Name: "Divi", Category: CatMisc, BodyMatch: []string{"et_pb_", "/wp-content/themes/Divi/"}},
	{Name: "Visual Composer", Category: CatMisc, BodyMatch: []string{"vc_row", "js_composer"}},

	// --- Added: modern stack coverage (audit techdetect-completeness) ---
	// Asset CDNs (high-value, appear on a huge fraction of sites).
	{Name: "jsDelivr", Category: CatCDN, BodyMatch: []string{"cdn.jsdelivr.net"}},
	{Name: "cdnjs", Category: CatCDN, BodyMatch: []string{"cdnjs.cloudflare.com"}},
	{Name: "unpkg", Category: CatCDN, BodyMatch: []string{"unpkg.com"}},
	{Name: "Google Hosted Libraries", Category: CatCDN, BodyMatch: []string{"ajax.googleapis.com/ajax/libs"}},
	// Ad / marketing / session-replay pixels.
	{Name: "TikTok Pixel", Category: CatAnalytics, BodyMatch: []string{"analytics.tiktok.com", "ttq.load"}},
	{Name: "LinkedIn Insight", Category: CatAnalytics, BodyMatch: []string{"snap.licdn.com", "_linkedin_data_partner_id"}},
	{Name: "Pinterest Tag", Category: CatAnalytics, BodyMatch: []string{"s.pinimg.com/ct", "pintrk("}},
	{Name: "Twitter Pixel", Category: CatAnalytics, BodyMatch: []string{"static.ads-twitter.com", "twq("}},
	{Name: "Microsoft Clarity", Category: CatAnalytics, BodyMatch: []string{"clarity.ms/tag"}},
	{Name: "Yandex Metrica", Category: CatAnalytics, BodyMatch: []string{"mc.yandex.ru/metrika"}},
	{Name: "Adobe Analytics", Category: CatAnalytics, BodyMatch: []string{".omtrdc.net", "adobedtm.com"}},
	// Modern site builders / CMS.
	{Name: "Framer", Category: CatCMS, BodyMatch: []string{"framerusercontent.com", "data-framer-"}},
	{Name: "Craft CMS", Category: CatCMS, Cookies: []string{"CraftSessionId"}},
	{Name: "Statamic", Category: CatCMS, MetaMatch: map[string]string{"generator": "statamic"}, Cookies: []string{"statamic_session"}},
	{Name: "Wagtail", Category: CatCMS, BodyMatch: []string{"wagtailcore", "/static/wagtailadmin/"}},
	{Name: "TYPO3", Category: CatCMS, BodyMatch: []string{"typo3temp/", "typo3conf/"}, MetaMatch: map[string]string{"generator": "typo3"}},
	{Name: "Remix", Category: CatFramework, BodyMatch: []string{"__remixContext", "/build/_shared/"}},
	{Name: "Astro", Category: CatFramework, BodyMatch: []string{"astro-island", "data-astro-"}, MetaMatch: map[string]string{"generator": "astro"}},
	{Name: "SvelteKit", Category: CatFramework, BodyMatch: []string{"__sveltekit", "/_app/immutable/"}},
	// WAF / API gateways (header-only; exact response-header names).
	{Name: "Kong", Category: CatSecurity, Headers: map[string]string{"Via": "kong", "X-Kong-Proxy-Latency": ""}, HeaderOnly: true},
	{Name: "AWS API Gateway", Category: CatSecurity, Headers: map[string]string{"X-Amzn-Apigw-Id": ""}, HeaderOnly: true},
	{Name: "Cloudflare Turnstile", Category: CatSecurity, BodyMatch: []string{"challenges.cloudflare.com/turnstile", "cf-turnstile"}},
	// PaaS origins (header-only).
	{Name: "Heroku", Category: CatCDN, Headers: map[string]string{"Via": "vegur"}, HeaderOnly: true},
	{Name: "Fly.io", Category: CatCDN, Headers: map[string]string{"Fly-Request-Id": ""}, HeaderOnly: true},
	{Name: "Kestrel", Category: CatServer, Headers: map[string]string{"Server": "Kestrel"}, HeaderOnly: true},
	{Name: "Traefik", Category: CatServer, Headers: map[string]string{"Server": "Traefik"}, HeaderOnly: true},
	// Common JS/mapping/media libs (body).
	{Name: "Leaflet", Category: CatJS, BodyMatch: []string{"leaflet.js", "leaflet.css", "L.map("}},
	{Name: "Video.js", Category: CatJS, BodyMatch: []string{"video-js", "videojs"}},
	{Name: "Sentry", Category: CatJS, BodyMatch: []string{"sentry-cdn.com", "@sentry/browser", "Sentry.init"}},
	{Name: "Alpine.js", Category: CatFramework, BodyMatch: []string{"x-data", "alpinejs", "cdn.jsdelivr.net/npm/alpinejs"}},
	{Name: "htmx", Category: CatJS, BodyMatch: []string{"htmx.org", "hx-get", "hx-post"}},
}

// MatchFingerprint checks if a fingerprint matches the response
func MatchFingerprint(fp *Fingerprint, headers map[string]string, cookies []string, body string) bool {
	hit, _ := MatchFingerprintWithEvidence(fp, headers, cookies, body, strings.ToLower(body))
	return hit
}

// MatchFingerprintWithEvidence is the explanatory version of MatchFingerprint
// — returns the same boolean plus a short human-readable string describing
// the exact signal that triggered the match. UI surfaces this when the user
// clicks a tech chip to investigate. Returns ("", false) when nothing matches.
//
// lowerBody must equal strings.ToLower(body); callers compute it once per
// target and reuse it across the ~260-entry fingerprint loop to avoid
// ~130 MB of throwaway byte churn per target.
func MatchFingerprintWithEvidence(fp *Fingerprint, headers map[string]string, cookies []string, body, lowerBody string) (bool, string) {
	// Header match (any one match = true).
	for hdr, pattern := range fp.Headers {
		val, ok := headers[strings.ToLower(hdr)]
		if !ok {
			continue
		}
		if pattern == "" {
			return true, fmt.Sprintf("header %q present (value %q)", hdr, val)
		}
		if strings.Contains(strings.ToLower(val), strings.ToLower(pattern)) {
			return true, fmt.Sprintf("header %q value %q contains %q", hdr, val, pattern)
		}
	}
	// Cookie match.
	for _, cp := range fp.Cookies {
		for _, c := range cookies {
			if strings.Contains(strings.ToLower(c), strings.ToLower(cp)) {
				return true, fmt.Sprintf("cookie name %q matched (full name %q)", cp, c)
			}
		}
	}
	if fp.HeaderOnly {
		return false, ""
	}
	// Body substring match.
	for _, bm := range fp.BodyMatch {
		if strings.Contains(lowerBody, strings.ToLower(bm)) {
			return true, fmt.Sprintf("response body contains substring %q", bm)
		}
	}
	// <meta name=X content=Y> match.
	for name, valPat := range fp.MetaMatch {
		if matchMeta(lowerBody, strings.ToLower(name), strings.ToLower(valPat)) {
			return true, fmt.Sprintf("<meta name=%q> content contains %q", name, valPat)
		}
	}
	return false, ""
}

func matchMeta(body, name, valPattern string) bool {
	// Look for <meta name="X" content="...Y...">
	idx := 0
	for {
		pos := strings.Index(body[idx:], "<meta")
		if pos < 0 {
			break
		}
		pos += idx
		end := strings.Index(body[pos:], ">")
		if end < 0 {
			break
		}
		tag := body[pos : pos+end+1]
		if strings.Contains(tag, "name=\""+name+"\"") || strings.Contains(tag, "name='"+name+"'") {
			if strings.Contains(tag, valPattern) {
				return true
			}
		}
		idx = pos + end + 1
	}
	return false
}
