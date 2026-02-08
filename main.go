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
			// Steven Black's unified hosts — comprehensive and well-maintained
			"https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
			// AdGuard DNS filter
			"https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
			// Pete Lowe's ad/tracking server list
			"https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext",
			// Malware domain list
			"https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/malware",
			// Tracking domains
			"https://v.firebog.net/hosts/Easyprivacy.txt",
		},
		WhitelistFile: "/etc/pi-adblock/whitelist.txt",
		LogFile:       "/var/log/pi-adblock.log",
		WebUIAddr:     ":8080",
		RefreshHours:  24,
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
