package main

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

// ============================================================================
// ANSI Colors for Loki-style verbose output
// ============================================================================

const (
	Reset   = "\033[0m"
	Bold    = "\033[1m"
	Dim     = "\033[2m"
	Red     = "\033[31m"
	Green   = "\033[32m"
	Yellow  = "\033[33m"
	Blue    = "\033[34m"
	Magenta = "\033[35m"
	Cyan    = "\033[36m"
	White   = "\033[37m"
	Orange  = "\033[38;5;208m"
	Gray    = "\033[38;5;245m"
	Pink    = "\033[38;5;205m"
)

// VerboseLog prints Loki-style timestamped colored messages
func VerboseLog(level, category, msg string) {
	ts := time.Now().Format("15:04:05.000")
	var levelTag string
	switch level {
	case "INFO":
		levelTag = fmt.Sprintf("%s● INF%s", Bold+Green, Reset)
	case "WARN":
		levelTag = fmt.Sprintf("%s▲ WRN%s", Bold+Yellow, Reset)
	case "ERROR":
		levelTag = fmt.Sprintf("%s✖ ERR%s", Bold+Red, Reset)
	case "BLOCK":
		levelTag = fmt.Sprintf("%s⛔ BLK%s", Bold+Red, Reset)
	case "ALLOW":
		levelTag = fmt.Sprintf("%s✔ ALW%s", Bold+Green, Reset)
	case "LOAD":
		levelTag = fmt.Sprintf("%s↓ LOD%s", Bold+Cyan, Reset)
	case "START":
		levelTag = fmt.Sprintf("%s▶ RUN%s", Bold+Magenta, Reset)
	case "DONE":
		levelTag = fmt.Sprintf("%s✔ DON%s", Bold+Green, Reset)
	case "FAIL":
		levelTag = fmt.Sprintf("%s✖ FAL%s", Bold+Red, Reset)
	case "NET":
		levelTag = fmt.Sprintf("%s⇄ NET%s", Bold+Blue, Reset)
	default:
		levelTag = fmt.Sprintf("%s· ---%s", Dim, Reset)
	}
	catTag := fmt.Sprintf("%s[%s]%s", Cyan, category, Reset)
	fmt.Printf("%s%s%s %s %s %s\n", Gray, ts, Reset, levelTag, catTag, msg)
}

// ProgressBar renders an inline progress bar
func ProgressBar(current, total int, width int) string {
	if total == 0 {
		return ""
	}
	pct := float64(current) / float64(total)
	filled := int(pct * float64(width))
	if filled > width {
		filled = width
	}
	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	return fmt.Sprintf("%s%s%s %s%.0f%%%s", Green, bar, Reset, Bold, pct*100, Reset)
}

// ============================================================================
// Config
// ============================================================================

type Config struct {
	ListenAddr    string
	UpstreamDNS   []string
	WhitelistFile string
	LogFile       string
	WebUIAddr     string
	RefreshHours  int
}

// ============================================================================
// Stats
// ============================================================================

type Stats struct {
	mu             sync.RWMutex
	TotalQueries   uint64
	BlockedQueries uint64
	AllowedQueries uint64
	StartTime      time.Time
	RecentBlocked  []string
	CategoryHits   map[string]*uint64
}

func NewStats() *Stats {
	return &Stats{
		StartTime:    time.Now(),
		CategoryHits: make(map[string]*uint64),
	}
}

func (s *Stats) RecordQuery(blocked bool, domain string, category string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.TotalQueries++
	if blocked {
		s.BlockedQueries++
		s.RecentBlocked = append(s.RecentBlocked, domain)
		if len(s.RecentBlocked) > 100 {
			s.RecentBlocked = s.RecentBlocked[len(s.RecentBlocked)-100:]
		}
		if category != "" {
			if _, ok := s.CategoryHits[category]; !ok {
				var zero uint64
				s.CategoryHits[category] = &zero
			}
			atomic.AddUint64(s.CategoryHits[category], 1)
		}
	} else {
		s.AllowedQueries++
	}
}

func (s *Stats) GetStats() (uint64, uint64, uint64, time.Duration, []string, map[string]uint64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cats := make(map[string]uint64)
	for k, v := range s.CategoryHits {
		cats[k] = atomic.LoadUint64(v)
	}
	return s.TotalQueries, s.BlockedQueries, s.AllowedQueries,
		time.Since(s.StartTime), append([]string{}, s.RecentBlocked...), cats
}

// ============================================================================
// Blocklist with categories
// ============================================================================

type BlockEntry struct {
	Category string
}

type Blocklist struct {
	mu      sync.RWMutex
	domains map[string]BlockEntry
}

func NewBlocklist() *Blocklist {
	return &Blocklist{domains: make(map[string]BlockEntry)}
}

func (bl *Blocklist) IsBlocked(domain string) (bool, string) {
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")
	bl.mu.RLock()
	defer bl.mu.RUnlock()

	if entry, ok := bl.domains[domain]; ok {
		return true, entry.Category
	}
	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts)-1; i++ {
		parent := strings.Join(parts[i:], ".")
		if entry, ok := bl.domains[parent]; ok {
			return true, entry.Category
		}
	}
	return false, ""
}

func (bl *Blocklist) AddWithCategory(domain, category string) {
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")
	if domain == "" {
		return
	}
	bl.mu.Lock()
	defer bl.mu.Unlock()
	bl.domains[domain] = BlockEntry{Category: category}
}

func (bl *Blocklist) Remove(domain string) {
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")
	bl.mu.Lock()
	defer bl.mu.Unlock()
	delete(bl.domains, domain)
}

func (bl *Blocklist) Count() int {
	bl.mu.RLock()
	defer bl.mu.RUnlock()
	return len(bl.domains)
}

func (bl *Blocklist) CountByCategory() map[string]int {
	bl.mu.RLock()
	defer bl.mu.RUnlock()
	counts := make(map[string]int)
	for _, entry := range bl.domains {
		counts[entry.Category]++
	}
	return counts
}

func (bl *Blocklist) LoadFromURL(url string, category string) (int, error) {
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return 0, fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	count := 0
	scanner := bufio.NewScanner(resp.Body)
	buf := make([]byte, 0, 1024*1024)
	scanner.Buffer(buf, 10*1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}

		var domain string
		if strings.HasPrefix(line, "0.0.0.0") || strings.HasPrefix(line, "127.0.0.1") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				domain = parts[1]
			}
		} else if strings.HasPrefix(line, "||") && strings.HasSuffix(line, "^") {
			domain = strings.TrimPrefix(line, "||")
			domain = strings.TrimSuffix(domain, "^")
		} else if !strings.Contains(line, " ") && !strings.Contains(line, "/") && strings.Contains(line, ".") {
			domain = line
		}

		domain = strings.TrimSpace(domain)
		if domain != "" && domain != "localhost" && domain != "localhost.localdomain" &&
			domain != "broadcasthost" && domain != "local" && !strings.HasPrefix(domain, "#") {
			bl.AddWithCategory(domain, category)
			count++
		}
	}
	return count, scanner.Err()
}

func (bl *Blocklist) LoadWhitelist(filepath string) (int, error) {
	file, err := os.Open(filepath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	defer file.Close()

	count := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			bl.Remove(line)
			count++
		}
	}
	return count, scanner.Err()
}

func (bl *Blocklist) LoadHardcodedDomains(domains []string, category string) int {
	count := 0
	for _, d := range domains {
		d = strings.TrimSpace(d)
		if d != "" && !strings.HasPrefix(d, "#") && !strings.HasPrefix(d, "*") {
			bl.AddWithCategory(d, category)
			count++
		}
	}
	return count
}

// ============================================================================
// Hardcoded domain lists
// ============================================================================

func getErrorMonitoringDomains() []string {
	return []string{
		// Sentry
		"sentry.io", "browser.sentry-cdn.com", "ingest.sentry.io", "sentry-cdn.com",
		"o0.ingest.sentry.io", "o1.ingest.sentry.io", "o2.ingest.sentry.io",
		"o3.ingest.sentry.io", "o4.ingest.sentry.io", "o5.ingest.sentry.io",
		// Bugsnag
		"bugsnag.com", "notify.bugsnag.com", "sessions.bugsnag.com", "api.bugsnag.com", "app.bugsnag.com",
		// Rollbar
		"rollbar.com", "api.rollbar.com",
		// Raygun
		"raygun.com", "api.raygun.com", "raygun.io", "api.raygun.io",
		// Datadog RUM
		"browser-intake-datadoghq.com", "browser-intake-datadoghq.eu",
		"browser-intake-us3-datadoghq.com", "browser-intake-us5-datadoghq.com",
		"rum.browser-intake-datadoghq.com", "rum-http-intake.logs.datadoghq.com",
		// LogRocket
		"logrocket.com", "r.lr-ingest.io", "r.lr-in.com", "cdn.lr-ingest.io", "cdn.lr-in.com",
		// Airbrake
		"airbrake.io", "api.airbrake.io", "collect.airbrake.io",
		// TrackJS
		"trackjs.com", "usage.trackjs.com", "capture.trackjs.com",
		// New Relic Browser
		"js-agent.newrelic.com", "bam.nr-data.net", "bam-cell.nr-data.net",
		// Honeybadger
		"honeybadger.io", "api.honeybadger.io",
		// AppSignal
		"appsignal.com", "push.appsignal.com",
		// Crashlytics
		"firebase-crashlytics.google.com", "crashlyticsreports-pa.googleapis.com",
		// FullStory
		"fullstory.com", "rs.fullstory.com", "edge.fullstory.com",
		// Highlight
		"highlight.io", "pub.highlight.io", "pri.highlight.run",
		// Elastic APM
		"apm.elastic.co",
		// Zipy
		"zipy.ai", "api.zipy.ai",
	}
}

func getAnalyticsDomains() []string {
	return []string{
		// Google Analytics / Tag Manager
		"google-analytics.com", "www.google-analytics.com", "ssl.google-analytics.com",
		"analytics.google.com", "googletagmanager.com", "www.googletagmanager.com",
		"tagmanager.google.com", "googletagservices.com",
		"pagead2.googlesyndication.com", "googleadservices.com", "www.googleadservices.com",
		"stats.g.doubleclick.net", "ad.doubleclick.net", "cm.g.doubleclick.net",
		// Hotjar
		"hotjar.com", "static.hotjar.com", "script.hotjar.com", "vars.hotjar.com",
		"in.hotjar.com", "vc.hotjar.io", "surveys.hotjar.com", "insights.hotjar.com",
		// Yandex Metrica
		"mc.yandex.ru", "mc.yandex.com", "metrika.yandex.ru", "metrica.yandex.com",
		"informer.yandex.ru", "webvisor.com", "an.yandex.ru",
		// Mixpanel
		"mixpanel.com", "api.mixpanel.com", "cdn.mxpnl.com", "api-js.mixpanel.com",
		// Amplitude
		"amplitude.com", "api.amplitude.com", "api2.amplitude.com", "cdn.amplitude.com",
		// Heap
		"heap.io", "heapanalytics.com", "cdn.heapanalytics.com",
		// Segment
		"segment.io", "segment.com", "api.segment.io", "cdn.segment.io", "cdn.segment.com",
		// Adobe Analytics
		"omtrdc.net", "2o7.net", "demdex.net", "everesttech.net", "adobedtm.com",
		// Kissmetrics
		"kissmetrics.com", "trk.kissmetrics.com", "i.kissmetrics.com",
		// Crazy Egg
		"crazyegg.com", "script.crazyegg.com", "dnn506yrbagrg.cloudfront.net",
		// Mouseflow
		"mouseflow.com", "o2.mouseflow.com",
		// Lucky Orange
		"luckyorange.com", "cdn.luckyorange.com", "w1.luckyorange.com",
		"upload.luckyorange.net", "cs.luckyorange.net", "realtime.luckyorange.com",
		// Smartlook
		"smartlook.com", "rec.smartlook.com", "manager.smartlook.com", "web-sdk.smartlook.com",
		// Inspectlet
		"inspectlet.com", "cdn.inspectlet.com", "hn.inspectlet.com",
		// Clicky
		"getclicky.com", "static.getclicky.com", "in.getclicky.com",
		// Chartbeat
		"chartbeat.com", "static.chartbeat.com", "ping.chartbeat.net",
		// Quantcast
		"quantserve.com", "quantcast.com", "pixel.quantserve.com",
		// ComScore
		"scorecardresearch.com", "b.scorecardresearch.com", "sb.scorecardresearch.com",
		// StatCounter
		"statcounter.com", "c.statcounter.com",
		// Woopra
		"woopra.com", "static.woopra.com",
		// PostHog
		"posthog.com", "app.posthog.com", "eu.posthog.com",
		// Pendo
		"pendo.io", "cdn.pendo.io", "app.pendo.io",
		// Snowplow
		"snowplow.io", "snowplowanalytics.com",
		// Plausible
		"plausible.io",
		// Matomo
		"matomo.cloud", "piwik.pro",
	}
}

func getScriptCDNBlockDomains() []string {
	return []string{
		// Ad script delivery
		"pagead2.googlesyndication.com", "tpc.googlesyndication.com",
		"adservice.google.com", "partner.googleadservices.com",
		"securepubads.g.doubleclick.net",
		// Popup / redirect networks
		"popads.net", "serve.popads.net", "pop.doublepimp.com",
		"popcash.net", "popmyads.com",
		"propellerads.com", "ad.propellerads.com",
		"go.pub2srv.com", "go.oclasrv.com", "go.onclasrv.com",
		"srv.clickfuse.com",
		"syndication.exoclick.com", "main.exoclick.com", "ads.exoclick.com", "static.exoclick.com",
		// Interstitial / overlay networks
		"adsterra.com", "www.adsterra.com", "ad.adsterra.com", "hb.adsterra.com",
		"syndication.realsrv.com", "a.realsrv.com", "s.realsrv.com",
		"jads.co", "juicyads.com", "tsyndicate.com", "syndication.dynsrvtag.com",
		// Clickjacking / URL shortener scams
		"adf.ly", "sh.st", "bc.vc", "j.gs", "q.gs",
		"shortify.com", "linkbucks.com", "adcrun.ch",
		// Video overlay ad networks
		"vidoomy.com", "vid.springserve.com", "cdn.vidible.tv",
		"vid.unrulymedia.com", "ads.undertone.com",
		"cdn.spotxcdn.com", "search.spotxchange.com", "t.myvisualiq.net",
		// Push notification spam
		"push.pub", "pushance.com", "notifpush.com", "pushails.com",
		"pushwelcome.com", "push-news.net", "pushnews.eu",
		"trustedpush.com", "pushsar.com",
		"check-you-robot.site", "confirmedyou.com", "topnotifications.online",
		"allownotice.com", "allnotifys.com", "allowallpush.com",
		"subscribesstar.com", "younotifications.com",
		// Mobile redirect / app install scam
		"bodelen.com", "atrfrg.xyz", "go.onclckds.com",
		"trafficjunky.com", "trafficstars.com", "a.trafficstars.com",
		"ad-maven.com", "ad-stacks.com", "admaven.com",
	}
}

func getRedirectPopupDomains() []string {
	return []string{
		// Redirect chains
		"install.app-ede.com", "go.redirectingat.com", "track.adform.net",
		"redirect.viglink.com", "go.skimresources.com",
		// Fake download buttons
		"cdn.downloadsfreefile.com", "dl-protect.net", "download-instantly.com",
		"downloadsoftware.link", "freefilesdownloader.com",
		"getfiles.org", "getmyfiles.org", "get-your.download",
		// Browser notification hijackers / fake virus pages
		"alert-defenders.com", "antivirus-check.net", "browser-check.online",
		"cleandevice.online", "device-guards.com", "device-safety.com",
		"is-your-device-secure.com", "mobile-check.online",
		"phone-alerts.com", "phone-protector.com", "protection-scan.com",
		"safe-device.com", "scan-device.com", "security-alert.online",
		"security-scanner.online", "virus-alert.online", "virus-check.online",
		"your-device-is.com", "your-phone-is-infected.com",
		// Survey / reward scams
		"claim-your-prize.com", "congratulations-you-won.com",
		"free-reward.com", "giftcard-reward.com", "prize-claim.com",
		"reward-zone.com", "spin-the-wheel.com",
		"winner-notification.com", "you-have-won.com",
		// "You've won!" popup networks
		"lp.wickedreports.com", "clicksgear.com", "onclicksuper.com",
		"go.affiliaxe.com", "offerimage.com", "go.oclaserver.com", "go.mobisla.com",
	}
}

// ============================================================================
// Remote blocklist sources
// ============================================================================

type BlocklistSource struct {
	URL      string
	Category string
	Name     string
}

func getAllSources() []BlocklistSource {
	return []BlocklistSource{
		// UNIFIED
		{"https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn-social/hosts", "blocklist", "StevenBlack Unified"},
		{"https://big.oisd.nl/domainswild", "blocklist", "OISD Big"},
		// ADVERTISING
		{"https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt", "blocklist", "AdGuard DNS"},
		{"https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext", "blocklist", "Pete Lowe Ads"},
		{"https://adaway.org/hosts.txt", "blocklist", "AdAway"},
		{"https://someonewhocares.org/hosts/zero/hosts", "blocklist", "Dan Pollock"},
		{"https://v.firebog.net/hosts/Easylist.txt", "blocklist", "EasyList"},
		{"https://v.firebog.net/hosts/Admiral.txt", "blocklist", "Admiral"},
		{"https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt", "blocklist", "Anudeep Ads"},
		{"https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt", "blocklist", "Disconnect Ads"},
		// TRACKING
		{"https://v.firebog.net/hosts/Easyprivacy.txt", "analytics", "EasyPrivacy"},
		{"https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt", "analytics", "Disconnect Tracking"},
		{"https://www.github.developerdan.com/hosts/lists/ads-and-tracking-extended.txt", "analytics", "Lightswitch05 Tracking"},
		{"https://v.firebog.net/hosts/Prigent-Crypto.txt", "blocklist", "Prigent Crypto"},
		{"https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt", "analytics", "Windows Spy Blocker"},
		{"https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV.txt", "analytics", "Perflyst SmartTV"},
		{"https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/android-tracking.txt", "analytics", "Perflyst Android"},
		{"https://raw.githubusercontent.com/notracking/hosts-blocklists/master/hostnames.txt", "analytics", "NoTracking"},
		{"https://raw.githubusercontent.com/anudeepND/blacklist/master/facebook.txt", "analytics", "Facebook Tracking"},
		{"https://hostfiles.frogeye.fr/firstparty-trackers-hosts.txt", "analytics", "Frogeye 1st-Party"},
		// MALWARE / PHISHING
		{"https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/malware", "blocklist", "RPiList Malware"},
		{"https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/Phishing-Angriffe", "blocklist", "RPiList Phishing"},
		{"https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt", "blocklist", "DandelionSprout Malware"},
		{"https://urlhaus.abuse.ch/downloads/hostfile/", "blocklist", "URLhaus"},
		{"https://phishing.army/download/phishing_army_blocklist_extended.txt", "blocklist", "Phishing Army"},
		{"https://v.firebog.net/hosts/Prigent-Malware.txt", "blocklist", "Prigent Malware"},
		{"https://threatfox.abuse.ch/downloads/hostfile/", "blocklist", "ThreatFox"},
		{"https://gitlab.com/quidsup/notrack-blocklists/-/raw/master/notrack-malware.txt", "blocklist", "NoTrack Malware"},
		{"https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Risk/hosts", "blocklist", "FadeMind Risk"},
		{"https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Spam/hosts", "blocklist", "FadeMind Spam"},
		{"https://v.firebog.net/hosts/Shalla-mal.txt", "blocklist", "Shallalist"},
		// SUSPICIOUS
		{"https://www.github.developerdan.com/hosts/lists/hate-and-junk-extended.txt", "blocklist", "Lightswitch05 Junk"},
		{"https://zerodot1.gitlab.io/CoinBlockerLists/hosts_browser", "blocklist", "CoinBlocker"},
		// SCAM / FRAUD
		{"https://www.github.developerdan.com/hosts/lists/amp-hosts-extended.txt", "analytics", "AMP Tracking"},
		{"https://osint.digitalside.it/Threat-Intel/lists/latestdomains.txt", "blocklist", "DigitalSide Intel"},
		{"https://raw.githubusercontent.com/durablenapkin/scamblocklist/master/hosts.txt", "redirect-popup", "Durablenapkin Scams"},
		{"https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt", "redirect-popup", "Mitchellkrogza Phishing"},
		// POPUP / REDIRECT
		{"https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/spam.mails", "redirect-popup", "RPiList Spam"},
		{"https://v.firebog.net/hosts/Prigent-Gambling.txt", "redirect-popup", "Prigent Gambling"},
		{"https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt", "redirect-popup", "Spam404"},
		// PUPs
		{"https://www.github.developerdan.com/hosts/lists/tracking-aggressive-extended.txt", "analytics", "Aggressive Tracking"},
		{"https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.2o7Net/hosts", "analytics", "Adobe 2o7Net"},
		{"https://raw.githubusercontent.com/FadeMind/hosts.extras/master/UncheckyAds/hosts", "redirect-popup", "UncheckyAds PUPs"},
		{"https://raw.githubusercontent.com/PolishFiltersTeam/KADhosts/master/KADhosts.txt", "redirect-popup", "KADhosts"},
		// MOBILE SCAMS
		{"https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/AmazonFireTV.txt", "analytics", "Fire TV Tracking"},
		{"https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews/hosts", "redirect-popup", "StevenBlack FakeNews"},
		{"https://gitlab.com/quidsup/notrack-blocklists/-/raw/master/notrack-blocklist.txt", "redirect-popup", "NoTrack Blocklist"},
		{"https://raw.githubusercontent.com/anudeepND/blacklist/master/CoinMiner.txt", "blocklist", "CoinMiner"},
		{"https://raw.githubusercontent.com/mitchellkrogza/Badd-Boyz-Hosts/master/hosts", "redirect-popup", "Badd-Boyz"},
	}
}

// ============================================================================
// DNS Server
// ============================================================================

type DNSServer struct {
	config    Config
	blocklist *Blocklist
	stats     *Stats
	client    *dns.Client
}

func NewDNSServer(config Config, blocklist *Blocklist, stats *Stats) *DNSServer {
	return &DNSServer{
		config: config, blocklist: blocklist, stats: stats,
		client: &dns.Client{Timeout: 5 * time.Second},
	}
}

func (s *DNSServer) handleDNS(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) == 0 {
		return
	}

	question := r.Question[0]
	domain := question.Name
	qtype := dns.TypeToString[question.Qtype]
	clientIP := w.RemoteAddr().String()

	blocked, category := s.blocklist.IsBlocked(domain)

	if blocked {
		s.stats.RecordQuery(true, strings.TrimSuffix(domain, "."), category)

		catColor := Red
		switch category {
		case "error-monitoring":
			catColor = Magenta
		case "analytics":
			catColor = Orange
		case "script-cdn":
			catColor = Yellow
		case "redirect-popup":
			catColor = Pink
		}

		VerboseLog("BLOCK", "dns",
			fmt.Sprintf("%s%s%s ← %s%s%s %s(%s)%s %sfrom%s %s",
				Bold+Red, strings.TrimSuffix(domain, "."), Reset,
				catColor, category, Reset,
				Dim, qtype, Reset, Dim, Reset, Gray+clientIP+Reset))

		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.Authoritative = true

		switch question.Qtype {
		case dns.TypeA:
			msg.Answer = append(msg.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("0.0.0.0"),
			})
		case dns.TypeAAAA:
			msg.Answer = append(msg.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: question.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
				AAAA: net.ParseIP("::"),
			})
		default:
			msg.Rcode = dns.RcodeNameError
		}
		w.WriteMsg(msg)
		return
	}

	s.stats.RecordQuery(false, strings.TrimSuffix(domain, "."), "")

	VerboseLog("ALLOW", "dns",
		fmt.Sprintf("%s%s%s %s(%s)%s %sfrom%s %s",
			Green, strings.TrimSuffix(domain, "."), Reset,
			Dim, qtype, Reset, Dim, Reset, Gray+clientIP+Reset))

	for _, upstream := range s.config.UpstreamDNS {
		resp, rtt, err := s.client.Exchange(r, upstream)
		if err == nil {
			resp.Id = r.Id
			VerboseLog("NET", "upstream",
				fmt.Sprintf("  %s→%s %s%s%s %s(%s)%s",
					Dim, Reset, Blue, upstream, Reset, Dim, rtt.Round(time.Millisecond), Reset))
			w.WriteMsg(resp)
			return
		}
	}

	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Rcode = dns.RcodeServerFailure
	VerboseLog("FAIL", "upstream", fmt.Sprintf("%sAll upstreams failed for %s%s", Red, domain, Reset))
	w.WriteMsg(msg)
}

// ============================================================================
// Web UI
// ============================================================================

func startWebUI(addr string, blocklist *Blocklist, stats *Stats) {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		total, blocked, allowed, uptime, recent, cats := stats.GetStats()
		catCounts := blocklist.CountByCategory()
		var pct float64
		if total > 0 {
			pct = float64(blocked) / float64(total) * 100
		}

		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<!DOCTYPE html><html><head>
<title>Blackhole-Pi</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="5">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'SF Mono',Monaco,monospace;background:#0a0e14;color:#c9d1d9;padding:20px}
h1{color:#58a6ff;margin-bottom:4px;font-size:24px}
.sub{color:#6e7681;font-size:12px;margin-bottom:20px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin-bottom:20px}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:14px}
.card .l{font-size:10px;color:#6e7681;text-transform:uppercase;letter-spacing:1px;margin-bottom:2px}
.card .v{font-size:22px;font-weight:bold;color:#58a6ff}
.card .v.r{color:#f85149}.card .v.g{color:#3fb950}
.cats{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:8px;margin-bottom:20px}
.cat{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:10px;display:flex;justify-content:space-between}
.cat .n{font-size:11px;color:#8b949e}.cat .c{font-size:16px;font-weight:bold;color:#58a6ff}
.rec{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:14px}
.rec h2{font-size:12px;color:#6e7681;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px}
.rec ul{list-style:none}.rec li{padding:2px 0;font-size:11px;color:#f85149;border-bottom:1px solid #21262d}
</style></head><body>
<h1>🛡️ Blackhole-Pi</h1>
<div class="sub">DNS Sinkhole • Ads • Analytics • Error Monitoring • Popups</div>
<div class="grid">
<div class="card"><div class="l">Uptime</div><div class="v">%s</div></div>
<div class="card"><div class="l">Blocklist</div><div class="v">%s</div></div>
<div class="card"><div class="l">Queries</div><div class="v">%d</div></div>
<div class="card"><div class="l">Blocked</div><div class="v r">%d (%.1f%%)</div></div>
<div class="card"><div class="l">Allowed</div><div class="v g">%d</div></div>
</div><div class="cats">`,
			formatDuration(uptime), formatCount(blocklist.Count()), total, blocked, pct, allowed)

		catInfo := []struct{ key, icon, label string }{
			{"error-monitoring", "🔍", "Error Monitoring"},
			{"analytics", "📊", "Analytics"},
			{"script-cdn", "📜", "Script CDNs"},
			{"redirect-popup", "🔗", "Redirects/Popups"},
			{"blocklist", "🛡️", "General Blocklist"},
		}
		for _, ci := range catInfo {
			fmt.Fprintf(w, `<div class="cat"><span class="n">%s %s<br><small>%s domains</small></span><span class="c">%d hits</span></div>`,
				ci.icon, ci.label, formatCount(catCounts[ci.key]), cats[ci.key])
		}

		fmt.Fprint(w, `</div><div class="rec"><h2>Recently Blocked</h2><ul>`)
		for i := len(recent) - 1; i >= 0 && i >= len(recent)-25; i-- {
			fmt.Fprintf(w, `<li>%s</li>`, recent[i])
		}
		fmt.Fprint(w, `</ul></div></body></html>`)
	})

	mux.HandleFunc("/api/stats", func(w http.ResponseWriter, r *http.Request) {
		total, blocked, allowed, uptime, _, cats := stats.GetStats()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"total":%d,"blocked":%d,"allowed":%d,"uptime":"%s","blocklist_size":%d,"categories":{`,
			total, blocked, allowed, formatDuration(uptime), blocklist.Count())
		first := true
		for k, v := range cats {
			if !first {
				fmt.Fprint(w, ",")
			}
			fmt.Fprintf(w, `"%s":%d`, k, v)
			first = false
		}
		fmt.Fprint(w, "}}")
	})

	VerboseLog("START", "webui", fmt.Sprintf("Dashboard at %shttp://0.0.0.0%s%s", Blue+Bold, addr, Reset))
	go http.ListenAndServe(addr, mux)
}

func formatDuration(d time.Duration) string {
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60
	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm", days, hours, mins)
	}
	return fmt.Sprintf("%dh %dm", hours, mins)
}

func formatCount(n int) string {
	if n >= 1000000 {
		return fmt.Sprintf("%.1fM", float64(n)/1000000)
	}
	if n >= 1000 {
		return fmt.Sprintf("%.1fK", float64(n)/1000)
	}
	return fmt.Sprintf("%d", n)
}

// ============================================================================
// Blocklist loading with verbose output
// ============================================================================

func loadAllBlocklists(blocklist *Blocklist, config Config) {
	startTime := time.Now()

	fmt.Println()
	VerboseLog("START", "init", fmt.Sprintf("%s═══════════════════════════════════════════════════%s", Bold+Cyan, Reset))
	VerboseLog("START", "init", fmt.Sprintf("%s  BLACKHOLE-PI • Loading Protection Rules%s", Bold+White, Reset))
	VerboseLog("START", "init", fmt.Sprintf("%s═══════════════════════════════════════════════════%s", Bold+Cyan, Reset))
	fmt.Println()

	// Phase 1: Hardcoded
	VerboseLog("LOAD", "hardcoded", fmt.Sprintf("%sPhase 1/3:%s Loading hardcoded domain rules...", Bold+Yellow, Reset))
	fmt.Println()

	errMon := getErrorMonitoringDomains()
	c := blocklist.LoadHardcodedDomains(errMon, "error-monitoring")
	VerboseLog("DONE", "error-monitoring",
		fmt.Sprintf("  %s✔%s Sentry, Bugsnag, Rollbar, Datadog, LogRocket, NewRelic   %s+%d%s", Green, Reset, Bold+Green, c, Reset))

	analytics := getAnalyticsDomains()
	c = blocklist.LoadHardcodedDomains(analytics, "analytics")
	VerboseLog("DONE", "analytics",
		fmt.Sprintf("  %s✔%s Google Analytics, Hotjar, Yandex, Mixpanel, Amplitude   %s+%d%s", Green, Reset, Bold+Green, c, Reset))

	scripts := getScriptCDNBlockDomains()
	c = blocklist.LoadHardcodedDomains(scripts, "script-cdn")
	VerboseLog("DONE", "script-cdn",
		fmt.Sprintf("  %s✔%s PopAds, PropellerAds, ExoClick, push spam, overlays   %s+%d%s", Green, Reset, Bold+Green, c, Reset))

	redirects := getRedirectPopupDomains()
	c = blocklist.LoadHardcodedDomains(redirects, "redirect-popup")
	VerboseLog("DONE", "redirect-popup",
		fmt.Sprintf("  %s✔%s Fake alerts, scam downloads, clickjacking, rewards   %s+%d%s", Green, Reset, Bold+Green, c, Reset))

	fmt.Println()
	VerboseLog("INFO", "hardcoded",
		fmt.Sprintf("  Hardcoded total: %s%d%s domains across %s4 categories%s",
			Bold+Cyan, blocklist.Count(), Reset, Bold, Reset))

	// Phase 2: Remote
	fmt.Println()
	VerboseLog("LOAD", "remote", fmt.Sprintf("%sPhase 2/3:%s Downloading remote blocklists...", Bold+Yellow, Reset))
	fmt.Println()

	sources := getAllSources()
	totalSrc := len(sources)
	ok, fail, totalDom := 0, 0, 0

	for i, src := range sources {
		progress := ProgressBar(i+1, totalSrc, 20)
		VerboseLog("LOAD", "fetch",
			fmt.Sprintf("  %s [%d/%d] %s%s%s", progress, i+1, totalSrc, Cyan, src.Name, Reset))

		t := time.Now()
		count, err := blocklist.LoadFromURL(src.URL, src.Category)
		d := time.Since(t).Round(time.Millisecond)

		if err != nil {
			fail++
			VerboseLog("FAIL", "fetch",
				fmt.Sprintf("         %s✖ %s — %s%s", Red, src.Name, err, Reset))
		} else {
			ok++
			totalDom += count
			VerboseLog("DONE", "fetch",
				fmt.Sprintf("         %s✔%s %s+%d%s domains  %s%s%s", Green, Reset, Bold+Green, count, Reset, Dim, d, Reset))
		}
	}

	fmt.Println()
	VerboseLog("INFO", "remote",
		fmt.Sprintf("  Sources: %s%d/%d%s OK, %s%d%s failed  •  Raw: %s%s%s domains",
			Bold+Green, ok, totalSrc, Reset, Bold+Red, fail, Reset, Bold+Cyan, formatCount(totalDom), Reset))

	// Phase 3: Whitelist
	fmt.Println()
	VerboseLog("LOAD", "whitelist", fmt.Sprintf("%sPhase 3/3:%s Applying whitelist...", Bold+Yellow, Reset))

	wl, err := blocklist.LoadWhitelist(config.WhitelistFile)
	if err != nil {
		VerboseLog("WARN", "whitelist", fmt.Sprintf("  %s▲ %v%s", Yellow, err, Reset))
	} else {
		VerboseLog("DONE", "whitelist",
			fmt.Sprintf("  %s✔%s Removed %s%d%s whitelisted domains", Green, Reset, Bold, wl, Reset))
	}

	elapsed := time.Since(startTime).Round(time.Millisecond)

	// Summary
	fmt.Println()
	VerboseLog("START", "summary", fmt.Sprintf("%s═══════════════════════════════════════════════════%s", Bold+Green, Reset))
	VerboseLog("INFO", "summary",
		fmt.Sprintf("  %sTotal unique blocked domains: %s%s%s", Bold+White, Bold+Cyan, formatCount(blocklist.Count()), Reset))

	catCounts := blocklist.CountByCategory()
	icons := map[string]string{
		"error-monitoring": "🔍", "analytics": "📊",
		"script-cdn": "📜", "redirect-popup": "🔗", "blocklist": "🛡️",
	}
	for cat, cnt := range catCounts {
		icon := icons[cat]
		if icon == "" {
			icon = "•"
		}
		VerboseLog("INFO", "summary",
			fmt.Sprintf("    %s %-20s %s%s%s", icon, cat, Bold, formatCount(cnt), Reset))
	}

	VerboseLog("INFO", "summary", fmt.Sprintf("  %sLoaded in %s%s%s", Dim, Reset+Bold+Green, elapsed, Reset))
	VerboseLog("START", "summary", fmt.Sprintf("%s═══════════════════════════════════════════════════%s", Bold+Green, Reset))
	fmt.Println()
}

// ============================================================================
// Main
// ============================================================================

func defaultConfig() Config {
	return Config{
		ListenAddr: ":53",
		UpstreamDNS: []string{
			"1.1.1.1:53",
			"1.0.0.1:53",
			"9.9.9.9:53",
			"8.8.8.8:53",
		},
		WhitelistFile: "/etc/pi-adblock/whitelist.txt",
		LogFile:       "/var/log/pi-adblock.log",
		WebUIAddr:     ":8080",
		RefreshHours:  12,
	}
}

func main() {
	config := defaultConfig()

	fmt.Printf("%s%s", Bold+Cyan, `
    ██████╗ ██╗      █████╗  ██████╗██╗  ██╗██╗  ██╗ ██████╗ ██╗     ███████╗
    ██╔══██╗██║     ██╔══██╗██╔════╝██║ ██╔╝██║  ██║██╔═══██╗██║     ██╔════╝
    ██████╔╝██║     ███████║██║     █████╔╝ ███████║██║   ██║██║     █████╗
    ██╔══██╗██║     ██╔══██║██║     ██╔═██╗ ██╔══██║██║   ██║██║     ██╔══╝
    ██████╔╝███████╗██║  ██║╚██████╗██║  ██╗██║  ██║╚██████╔╝███████╗███████╗
    ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚══════╝
`)
	fmt.Printf("%s    DNS Sinkhole • Ads • Analytics • Error Monitoring • Popups%s  %sv2.0%s\n\n", Bold+White, Reset, Dim, Reset)

	blocklist := NewBlocklist()
	stats := NewStats()

	loadAllBlocklists(blocklist, config)

	// Periodic refresh
	go func() {
		ticker := time.NewTicker(time.Duration(config.RefreshHours) * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			VerboseLog("INFO", "refresh", fmt.Sprintf("%s🔄 Refreshing blocklists...%s", Yellow, Reset))
			loadAllBlocklists(blocklist, config)
		}
	}()

	startWebUI(config.WebUIAddr, blocklist, stats)

	dnsServer := NewDNSServer(config, blocklist, stats)
	dns.HandleFunc(".", dnsServer.handleDNS)

	udpServer := &dns.Server{Addr: config.ListenAddr, Net: "udp"}
	tcpServer := &dns.Server{Addr: config.ListenAddr, Net: "tcp"}

	go func() {
		VerboseLog("START", "dns", fmt.Sprintf("UDP listener on %s%s%s", Bold+Blue, config.ListenAddr, Reset))
		if err := udpServer.ListenAndServe(); err != nil {
			VerboseLog("ERROR", "dns", fmt.Sprintf("%sFATAL: UDP failed: %v%s", Red, err, Reset))
			os.Exit(1)
		}
	}()
	go func() {
		VerboseLog("START", "dns", fmt.Sprintf("TCP listener on %s%s%s", Bold+Blue, config.ListenAddr, Reset))
		if err := tcpServer.ListenAndServe(); err != nil {
			VerboseLog("ERROR", "dns", fmt.Sprintf("%sFATAL: TCP failed: %v%s", Red, err, Reset))
			os.Exit(1)
		}
	}()

	VerboseLog("START", "main", fmt.Sprintf("%s🛡️  BLACKHOLE-PI IS ACTIVE — ALL SYSTEMS GO%s", Bold+Green, Reset))
	VerboseLog("INFO", "main", fmt.Sprintf("  DNS: %s%s%s  •  Web: %shttp://0.0.0.0%s%s  •  Domains: %s%s%s",
		Blue, config.ListenAddr, Reset, Blue, config.WebUIAddr, Reset, Cyan+Bold, formatCount(blocklist.Count()), Reset))
	fmt.Println()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	fmt.Println()
	VerboseLog("INFO", "shutdown", fmt.Sprintf("%sGraceful shutdown...%s", Yellow, Reset))
	udpServer.Shutdown()
	tcpServer.Shutdown()
	VerboseLog("DONE", "shutdown", fmt.Sprintf("%s👋 Goodbye!%s", Green, Reset))
	fmt.Println()
}
