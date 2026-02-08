package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

// Config holds the application configuration
type Config struct {
	ListenAddr    string   // DNS listen address (e.g. ":53")
	UpstreamDNS   []string // Upstream DNS servers
	BlocklistURLs []string // URLs to download blocklists from
	WhitelistFile string   // Path to local whitelist file
	LogFile       string   // Path to log file
	WebUIAddr     string   // Web dashboard address
	RefreshHours  int      // How often to refresh blocklists
}

// Stats tracks blocking statistics
type Stats struct {
	mu             sync.RWMutex
	TotalQueries   uint64
	BlockedQueries uint64
	AllowedQueries uint64
	StartTime      time.Time
	RecentBlocked  []string
}

func (s *Stats) RecordQuery(blocked bool, domain string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.TotalQueries++
	if blocked {
		s.BlockedQueries++
		s.RecentBlocked = append(s.RecentBlocked, domain)
		if len(s.RecentBlocked) > 50 {
			s.RecentBlocked = s.RecentBlocked[len(s.RecentBlocked)-50:]
		}
	} else {
		s.AllowedQueries++
	}
}

func (s *Stats) GetStats() (uint64, uint64, uint64, time.Duration, []string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.TotalQueries, s.BlockedQueries, s.AllowedQueries,
		time.Since(s.StartTime), append([]string{}, s.RecentBlocked...)
}

// Blocklist manages blocked domains
type Blocklist struct {
	mu      sync.RWMutex
	domains map[string]bool
}

func NewBlocklist() *Blocklist {
	return &Blocklist{
		domains: make(map[string]bool),
	}
}

func (bl *Blocklist) IsBlocked(domain string) bool {
	// Normalize: strip trailing dot
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")

	bl.mu.RLock()
	defer bl.mu.RUnlock()

	// Check exact match
	if bl.domains[domain] {
		return true
	}

	// Check parent domains (e.g. sub.ads.example.com -> ads.example.com -> example.com)
	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts)-1; i++ {
		parent := strings.Join(parts[i:], ".")
		if bl.domains[parent] {
			return true
		}
	}
	return false
}

func (bl *Blocklist) Add(domain string) {
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")
	bl.mu.Lock()
	defer bl.mu.Unlock()
	bl.domains[domain] = true
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

// LoadFromURL downloads a blocklist and adds domains
func (bl *Blocklist) LoadFromURL(url string) (int, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return 0, fmt.Errorf("failed to download %s: %w", url, err)
	}
	defer resp.Body.Close()

	count := 0
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}

		var domain string

		// Handle hosts-file format: "0.0.0.0 domain.com" or "127.0.0.1 domain.com"
		if strings.HasPrefix(line, "0.0.0.0") || strings.HasPrefix(line, "127.0.0.1") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				domain = parts[1]
			}
		} else if strings.HasPrefix(line, "||") && strings.HasSuffix(line, "^") {
			// Handle Adblock-style: "||domain.com^"
			domain = strings.TrimPrefix(line, "||")
			domain = strings.TrimSuffix(domain, "^")
		} else if !strings.Contains(line, " ") && strings.Contains(line, ".") {
			// Plain domain format
			domain = line
		}

		if domain != "" && domain != "localhost" && domain != "localhost.localdomain" &&
			domain != "broadcasthost" && domain != "local" {
			bl.Add(domain)
			count++
		}
	}

	return count, scanner.Err()
}

// LoadWhitelist removes whitelisted domains from the blocklist
func (bl *Blocklist) LoadWhitelist(filepath string) error {
	file, err := os.Open(filepath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // No whitelist file is fine
		}
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			bl.Remove(line)
		}
	}
	return scanner.Err()
}

// DNSServer handles DNS queries
type DNSServer struct {
	config    Config
	blocklist *Blocklist
	stats     *Stats
	client    *dns.Client
}

func NewDNSServer(config Config, blocklist *Blocklist, stats *Stats) *DNSServer {
	return &DNSServer{
		config:    config,
		blocklist: blocklist,
		stats:     stats,
		client: &dns.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// handleDNS processes incoming DNS queries
func (s *DNSServer) handleDNS(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) == 0 {
		return
	}

	question := r.Question[0]
	domain := question.Name

	// Check if domain is blocked
	if s.blocklist.IsBlocked(domain) {
		s.stats.RecordQuery(true, strings.TrimSuffix(domain, "."))
		log.Printf("BLOCKED: %s", domain)

		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.Authoritative = true

		// Return 0.0.0.0 for A records, :: for AAAA records
		switch question.Qtype {
		case dns.TypeA:
			msg.Answer = append(msg.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				A: net.ParseIP("0.0.0.0"),
			})
		case dns.TypeAAAA:
			msg.Answer = append(msg.Answer, &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				AAAA: net.ParseIP("::"),
			})
		default:
			msg.Rcode = dns.RcodeNameError
		}

		w.WriteMsg(msg)
		return
	}

	// Forward to upstream DNS
	s.stats.RecordQuery(false, strings.TrimSuffix(domain, "."))

	for _, upstream := range s.config.UpstreamDNS {
		resp, _, err := s.client.Exchange(r, upstream)
		if err == nil {
			resp.Id = r.Id
			w.WriteMsg(resp)
			return
		}
		log.Printf("Upstream %s failed: %v", upstream, err)
	}

	// All upstreams failed
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Rcode = dns.RcodeServerFailure
	w.WriteMsg(msg)
}

// startWebUI launches a simple status dashboard
func startWebUI(addr string, blocklist *Blocklist, stats *Stats) {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		total, blocked, allowed, uptime, recent := stats.GetStats()

		var pct float64
		if total > 0 {
			pct = float64(blocked) / float64(total) * 100
		}

		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
  <title>Pi Ad Blocker</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="refresh" content="10">
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, sans-serif; background: #0d1117; color: #c9d1d9; padding: 20px; }
    h1 { color: #58a6ff; margin-bottom: 20px; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }
    .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; }
    .card .label { font-size: 12px; color: #8b949e; text-transform: uppercase; margin-bottom: 4px; }
    .card .value { font-size: 28px; font-weight: bold; color: #58a6ff; }
    .card .value.blocked { color: #f85149; }
    .card .value.allowed { color: #3fb950; }
    .recent { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; }
    .recent h2 { font-size: 16px; color: #8b949e; margin-bottom: 12px; }
    .recent ul { list-style: none; }
    .recent li { padding: 4px 0; font-family: monospace; font-size: 13px; color: #f85149; border-bottom: 1px solid #21262d; }
  </style>
</head>
<body>
  <h1>🛡️ Pi Ad Blocker</h1>
  <div class="grid">
    <div class="card"><div class="label">Uptime</div><div class="value">%s</div></div>
    <div class="card"><div class="label">Domains Blocked</div><div class="value">%d</div></div>
    <div class="card"><div class="label">Total Queries</div><div class="value">%d</div></div>
    <div class="card"><div class="label">Blocked Queries</div><div class="value blocked">%d (%.1f%%)</div></div>
    <div class="card"><div class="label">Allowed Queries</div><div class="value allowed">%d</div></div>
  </div>
  <div class="recent">
    <h2>Recently Blocked</h2>
    <ul>`,
			formatDuration(uptime), blocklist.Count(), total, blocked, pct, allowed)

		// Show most recent first
		for i := len(recent) - 1; i >= 0 && i >= len(recent)-20; i-- {
			fmt.Fprintf(w, `<li>%s</li>`, recent[i])
		}

		fmt.Fprint(w, `</ul></div></body></html>`)
	})

	mux.HandleFunc("/api/stats", func(w http.ResponseWriter, r *http.Request) {
		total, blocked, allowed, uptime, _ := stats.GetStats()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"total":%d,"blocked":%d,"allowed":%d,"uptime":"%s","blocklist_size":%d}`,
			total, blocked, allowed, formatDuration(uptime), blocklist.Count())
	})

	log.Printf("Web dashboard at http://%s", addr)
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

func defaultConfig() Config {
	return Config{
		ListenAddr: ":53",
		UpstreamDNS: []string{
			"1.1.1.1:53", // Cloudflare
			"1.0.0.1:53", // Cloudflare backup
			"9.9.9.9:53", // Quad9
			"8.8.8.8:53", // Google
		},
		BlocklistURLs: []string{
			// ===== UNIFIED / COMPREHENSIVE =====
			// Steven Black's unified hosts (ads + malware + fakenews + gambling + social)
			"https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn-social/hosts",
			// OISD - one of the most comprehensive, curated blocklists
			"https://big.oisd.nl/domainswild",

			// ===== ADVERTISING =====
			// AdGuard DNS filter
			"https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
			// Pete Lowe's ad/tracking servers
			"https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext",
			// AdAway default blocklist
			"https://adaway.org/hosts.txt",
			// Dan Pollock's hosts file
			"https://someonewhocares.org/hosts/zero/hosts",
			// Winhelp ad servers
			"https://winhelp2002.mvps.org/hosts.txt",
			// EasyList (ads)
			"https://v.firebog.net/hosts/Easylist.txt",
			// AdGuard Mobile Ads filter
			"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_11_Mobile/filter.txt",
			// Admiral (anti-adblock) domains
			"https://v.firebog.net/hosts/Admiral.txt",
			// Anudeep's blacklist (ads)
			"https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt",
			// Yoyo ads
			"https://pgl.yoyo.org/adservers/serverlist.php?hostformat=nohtml&showintro=0&mimetype=plaintext",
			// Disconnect.me ads
			"https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt",

			// ===== TRACKING / TELEMETRY =====
			// EasyPrivacy (tracking)
			"https://v.firebog.net/hosts/Easyprivacy.txt",
			// Disconnect.me tracking
			"https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt",
			// Lightswitch05 Ads & Tracking
			"https://www.github.developerdan.com/hosts/lists/ads-and-tracking-extended.txt",
			// Prigent Ads
			"https://v.firebog.net/hosts/Prigent-Ads.txt",
			// Prigent Crypto (cryptomining)
			"https://v.firebog.net/hosts/Prigent-Crypto.txt",
			// Windows Spy Blocker (telemetry)
			"https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt",
			// Perflyst Smart TV tracking
			"https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV.txt",
			// Perflyst Android tracking
			"https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/android-tracking.txt",
			// NoTracking hosts blocklist
			"https://raw.githubusercontent.com/notracking/hosts-blocklists/master/hostnames.txt",
			// Anudeep's Facebook tracking
			"https://raw.githubusercontent.com/anudeepND/blacklist/master/facebook.txt",
			// Geoffrey Frogeye first-party trackers
			"https://hostfiles.frogeye.fr/firstparty-trackers-hosts.txt",

			// ===== MALWARE / PHISHING / RANSOMWARE =====
			// RPiList malware
			"https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/malware",
			// RPiList phishing
			"https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/Phishing-Angriffe",
			// DandelionSprout's Anti-Malware
			"https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt",
			// URLhaus malware distribution
			"https://urlhaus.abuse.ch/downloads/hostfile/",
			// Phishing Army
			"https://phishing.army/download/phishing_army_blocklist_extended.txt",
			// Mandiant APT threat domains
			"https://v.firebog.net/hosts/Prigent-Malware.txt",
			// Abuse.ch ThreatFox
			"https://threatfox.abuse.ch/downloads/hostfile/",
			// VeleSila threat intelligence
			"https://raw.githubusercontent.com/VeleSila/yhosts/master/hosts",
			// Quidsup NoTrack Malware
			"https://gitlab.com/quidsup/notrack-blocklists/-/raw/master/notrack-malware.txt",
			// FadeMind add.Risk
			"https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Risk/hosts",
			// FadeMind add.Spam
			"https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Spam/hosts",
			// Shallalist spam
			"https://v.firebog.net/hosts/Shalla-mal.txt",

			// ===== SUSPICIOUS / NEWLY REGISTERED DOMAINS =====
			// Lightswitch05 hate & junk
			"https://www.github.developerdan.com/hosts/lists/hate-and-junk-extended.txt",
			// Lightswitch05 dating services
			"https://www.github.developerdan.com/hosts/lists/dating-services-extended.txt",

			// ===== COIN MINERS / CRYPTO JACKING =====
			// ZeroDot1 CoinBlocker
			"https://zerodot1.gitlab.io/CoinBlockerLists/hosts_browser",

			// ===== SCAM / FRAUD / TECH SUPPORT SCAMS =====
			// Lightswitch05 amp-hosts (Google AMP tracking)
			"https://www.github.developerdan.com/hosts/lists/amp-hosts-extended.txt",
			// DigitalSide Threat-Intel
			"https://osint.digitalside.it/Threat-Intel/lists/latestdomains.txt",
			// Durablenapkin scam blocklist (fake virus alerts, tech support scams, "your phone is infected")
			"https://raw.githubusercontent.com/durablenapkin/scamblocklist/master/hosts.txt",
			// Mitchellkrogza Phishing Database
			"https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt",
			// Scam and fraud domains (elliotwutingfeng)
			"https://raw.githubusercontent.com/elliotwutingfeng/Inversion-DNSBL-Blocklists/main/Google_hostnames_light.txt",

			// ===== POPUP / PUSH NOTIFICATION SPAM / REDIRECTS =====
			// RPiList popup/redirect blocklist
			"https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/spam.mails",
			// Prigent Gambling (often source of scam popups)
			"https://v.firebog.net/hosts/Prigent-Gambling.txt",
			// Push notification spam domains (these power "your phone has a virus" mobile popups)
			"https://raw.githubusercontent.com/nickspaargaren/no-google/master/pihole-google.txt",
			// AdGuard Popups filter
			"https://raw.githubusercontent.com/nickspaargaren/pihole-google/master/nickspaargaren-google.txt",
			// Spam404
			"https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt",

			// ===== MALICIOUS DOWNLOADS / PUPs (Potentially Unwanted Programs) =====
			// Abuse.ch - active malware distribution URLs
			"https://urlhaus.abuse.ch/downloads/hostfile/",
			// Lightswitch05 tracking-aggressive (catches download wrappers)
			"https://www.github.developerdan.com/hosts/lists/tracking-aggressive-extended.txt",
			// FadeMind add.2o7Net (Adobe tracking/download wrappers)
			"https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.2o7Net/hosts",
			// FadeMind UncheckyAds (bundled software/PUP domains)
			"https://raw.githubusercontent.com/FadeMind/hosts.extras/master/UncheckyAds/hosts",
			// FadeMind add.Dead (dead malware domains)
			"https://raw.githubusercontent.com/FadeMind/hosts.extras/master/add.Dead/hosts",
			// PolishFiltersTeam KADhosts (scam/PUP/malware)
			"https://raw.githubusercontent.com/PolishFiltersTeam/KADhosts/master/KADhosts.txt",
			// Hectorm anti-malware/scam
			"https://raw.githubusercontent.com/hectorm/hmirror/master/data/adaway.org/list.txt",

			// ===== MOBILE-SPECIFIC SCAMS / FAKE ALERTS =====
			// Perflyst Android tracking (catches fake alert ad networks)
			"https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/AmazonFireTV.txt",
			// AdGuard Mobile Specific annoyances
			"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_17_TrackParam/filter.txt",
			// AdGuard Annoyances filter (popups, cookie notices, mobile overlays)
			"https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_14_Annoyances/filter.txt",
			// AdGuard URL Tracking filter
			"https://raw.githubusercontent.com/nickspaargaren/pihole-google/master/nickspaargaren-dnsmasq-google.txt",
			// StevenBlack fakenews extension (fake download buttons, scam news)
			"https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews/hosts",

			// ===== NEWLY REGISTERED / SUSPICIOUS DOMAINS =====
			// Newly registered domains are the #1 source of "your phone is hacked" scams
			// CoinBlocker browser list (cryptojacking popups)
			"https://zerodot1.gitlab.io/CoinBlockerLists/hosts",
			// Quidsup NoTrack blocklist (scam sites, malware, PUPs)
			"https://gitlab.com/quidsup/notrack-blocklists/-/raw/master/notrack-blocklist.txt",
			// anudeepND CoinMiner (crypto popup scams)
			"https://raw.githubusercontent.com/anudeepND/blacklist/master/CoinMiner.txt",
			// Badd-Boyz hosts (aggressive scam/malware blocking)
			"https://raw.githubusercontent.com/mitchellkrogza/Badd-Boyz-Hosts/master/hosts",
		},
		WhitelistFile: "/etc/pi-adblock/whitelist.txt",
		LogFile:       "/var/log/pi-adblock.log",
		WebUIAddr:     ":8080",
		RefreshHours:  12,
	}
}

func main() {
	config := defaultConfig()

	// Setup logging
	logFile, err := os.OpenFile(config.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		// Fall back to stdout if log file can't be opened
		log.Printf("Warning: couldn't open log file %s: %v (using stdout)", config.LogFile, err)
	} else {
		log.SetOutput(logFile)
		defer logFile.Close()
	}

	log.Println("=== Pi Ad Blocker Starting ===")

	// Initialize blocklist and stats
	blocklist := NewBlocklist()
	stats := &Stats{StartTime: time.Now()}

	// Load blocklists
	log.Println("Loading blocklists...")
	totalDomains := 0
	for _, url := range config.BlocklistURLs {
		count, err := blocklist.LoadFromURL(url)
		if err != nil {
			log.Printf("Warning: failed to load %s: %v", url, err)
			continue
		}
		totalDomains += count
		log.Printf("Loaded %d domains from %s", count, url)
	}
	log.Printf("Total blocked domains: %d (deduplicated: %d)", totalDomains, blocklist.Count())

	// Load whitelist
	if err := blocklist.LoadWhitelist(config.WhitelistFile); err != nil {
		log.Printf("Warning: whitelist error: %v", err)
	}

	// Periodic blocklist refresh
	go func() {
		ticker := time.NewTicker(time.Duration(config.RefreshHours) * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			log.Println("Refreshing blocklists...")
			for _, url := range config.BlocklistURLs {
				count, err := blocklist.LoadFromURL(url)
				if err != nil {
					log.Printf("Refresh warning: %s: %v", url, err)
					continue
				}
				log.Printf("Refreshed %d domains from %s", count, url)
			}
			blocklist.LoadWhitelist(config.WhitelistFile)
			log.Printf("Blocklist refreshed: %d domains", blocklist.Count())
		}
	}()

	// Start web dashboard
	startWebUI(config.WebUIAddr, blocklist, stats)

	// Start DNS server
	dnsServer := NewDNSServer(config, blocklist, stats)
	dns.HandleFunc(".", dnsServer.handleDNS)

	udpServer := &dns.Server{Addr: config.ListenAddr, Net: "udp"}
	tcpServer := &dns.Server{Addr: config.ListenAddr, Net: "tcp"}

	go func() {
		log.Printf("DNS server listening on %s (UDP)", config.ListenAddr)
		if err := udpServer.ListenAndServe(); err != nil {
			log.Fatalf("UDP server failed: %v", err)
		}
	}()

	go func() {
		log.Printf("DNS server listening on %s (TCP)", config.ListenAddr)
		if err := tcpServer.ListenAndServe(); err != nil {
			log.Fatalf("TCP server failed: %v", err)
		}
	}()

	fmt.Println("🛡️  Pi Ad Blocker is running!")
	fmt.Printf("   DNS server:  %s\n", config.ListenAddr)
	fmt.Printf("   Web UI:      http://localhost%s\n", config.WebUIAddr)
	fmt.Printf("   Blocked:     %d domains\n", blocklist.Count())
	fmt.Printf("   Upstream:    %v\n", config.UpstreamDNS)
	fmt.Println("\nPress Ctrl+C to stop.")

	// Wait for shutdown signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("Shutting down...")
	udpServer.Shutdown()
	tcpServer.Shutdown()
	fmt.Println("\nGoodbye!")
}
