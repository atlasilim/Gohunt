package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
)

// Renkli çıktı için yardımcılar
var (
	cyan    = color.New(color.FgCyan).SprintFunc()
	green   = color.New(color.FgGreen).SprintFunc()
	yellow  = color.New(color.FgYellow).SprintFunc()
	red     = color.New(color.FgRed).SprintFunc()
	magenta = color.New(color.FgMagenta).SprintFunc()
	bold    = color.New(color.Bold).SprintFunc()
)

// Subdomain durumu için struct
type SubdomainStatus struct {
	Name   string
	Status string // "Active", "Inactive", "Not Found"
}

// Sonuçları tutacak ana struct
type ScanResult struct {
	Target       string
	Subdomains   []SubdomainStatus
	OpenPorts    []PortInfo
	CVEs         []CVEInfo
	WebTechs     []string
	ReverseIP    string
	Whois        string
	VulnResults  []string
	ScanStart    string
	ScanDuration string
	ResolvedIP   string
	Errors       []string
	Warnings     []string
}

type PortInfo struct {
	Port    int
	Service string
	Banner  string
}

type CVEInfo struct {
	ID          string
	Description string
	Severity    string
	Source      string
	ExploitLink string
	CVSS        float64
}

// Banner
func printBanner() {
	fmt.Println(bold(red(` ██████╗  ██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗`)))
	fmt.Println(bold(red(`██╔════╝ ██╔═══██╗██║  ██║██║   ██║████╗  ██║╚══██╔══╝`)))
	fmt.Println(bold(red(`██║  ███╗██║   ██║███████║██║   ██║██╔██╗ ██║   ██║   `)))
	fmt.Println(bold(red(`██║   ██║██║   ██║██╔══██║██║   ██║██║╚██╗██║   ██║   `)))
	fmt.Println(bold(red(`╚██████╔╝╚██████╔╝██║  ██║╚██████╔╝██║ ╚████║   ██║   `)))
	fmt.Println(bold(red(` ╚═════╝  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   `)))
	fmt.Println(magenta("\n== GoHunt v1.0 - All-in-One Web Tool =="))
}

// Kapsamlı kullanım rehberi
func printUsage() {
	fmt.Println(bold(cyan("GoHunt v1.0 - All-in-One Web Tool")))
	fmt.Println(magenta("Developed by Mynex"))

	fmt.Println(bold("USAGE:"))
	fmt.Println("  gohunt --target <domain/ip> [OPTIONS]")

	fmt.Println(bold("BASIC OPTIONS:"))
	fmt.Println("  --target <domain>     Target domain or IP address")
	fmt.Println("  --all-in-one          Run all scans (default if none selected)")
	fmt.Println("  --verbose             Show verbose output")
	fmt.Println("  --help, -h            Show this help message")

	fmt.Println(bold("SCAN OPTIONS:"))
	fmt.Println("  --subdomain           Run subdomain scan")
	fmt.Println("  --port-scan           Run port scan")
	fmt.Println("  --cve-scan            Run CVE scan")
	fmt.Println("  --reverse-ip          Run reverse IP lookup")
	fmt.Println("  --whois               Run WHOIS lookup")
	fmt.Println("  --xss                 Run XSS test")
	fmt.Println("  --sqli                Run SQLi test")
	fmt.Println("  --lfi                 Run LFI test")

	fmt.Println(bold("OUTPUT FORMATS:"))
	fmt.Println("  --output <file>       Output file (.json, .html, .csv, .xml, .txt)")
	fmt.Println("  --log-file <file>     Log file")

	fmt.Println(bold("PERFORMANCE SETTINGS:"))
	fmt.Println("  --ports <list>        Ports to scan (default: 22,21,25,53,80,110,143,443,587,993,995,3306,5432,6379,8080,8443)")
	fmt.Println("  --port-timeout-ms <ms> Port connect timeout (default: 800)")
	fmt.Println("  --port-concurrency <n> Port scan concurrency (default: 200)")
	fmt.Println("  --sub-concurrency <n>  Subdomain scan concurrency (default: 150)")
	fmt.Println("  --http-timeout-ms <ms> HTTP request timeout (default: 4000)")
	fmt.Println("  --rate-limit-ps <n>    HTTP rate limit (default: 3)")

	fmt.Println(bold("OSINT SETTINGS:"))
	fmt.Println("  --osint               Collect subdomains from OSINT sources (default: on)")
	fmt.Println("  --osint-max <n>       OSINT subdomain upper limit (default: 5000)")
	fmt.Println("  --osint-timeout-ms <ms> OSINT request timeout (default: 10000)")
	fmt.Println("  --osint-rate-limit-ps <n> OSINT rate limit (default: 1)")

	fmt.Println(bold("SECURITY SETTINGS:"))
	fmt.Println("  --insecure-tls        Disable TLS verification (not recommended)")
	fmt.Println("  --ca-file <file>      Custom CA certificate file (PEM)")

	fmt.Println(bold("EXAMPLES:"))
	fmt.Println("  gohunt --target example.com")
	fmt.Println("  gohunt --target example.com --all-in-one --verbose")
	fmt.Println("  gohunt --target example.com --port-scan --ports 1-1024 --output report.json")
	fmt.Println("  gohunt --target example.com --subdomain --osint-max 1000 --rate-limit-ps 5")
	fmt.Println("  gohunt --target example.com --all-in-one --output report.csv --log-file scan.log")

	fmt.Println(bold("NOTES:"))
	fmt.Println("  • When --all-in-one is used, all scans run automatically")
	fmt.Println("  • If no scan is selected, all scans run by default")
	fmt.Println("  • For large targets adjust --osint-max and --rate-limit-ps")
	fmt.Println("  • Increase --port-concurrency and --sub-concurrency for faster scans")

	fmt.Println("© 2025 GoHunt - Developed by Mynex")
}

// ---- Global tarama ayarları (flag'lerden doldurulur) ----
var (
	portsArg        string
	portTimeout     time.Duration
	portConcurrency int
	subWordlistPath string
	subTimeout      time.Duration
	subConcurrency  int
	httpTimeout     time.Duration
	schemeMode      string // auto|http|https
	logFilePath     string
	retries         int
	retryBackoff    time.Duration
	scanMode        string // connect|syn (syn şu an stub)
	enableOSINT     bool
	showProgress    bool
	rateLimitPerSec int
	osintMaxResults int
	insecureTLS     bool
	caFile          string
	caPool          *x509.CertPool
	osintTimeout    time.Duration
	osintRetries    int
	osintBackoff    time.Duration
	osintRateLimit  int
)

// logger
var logger = log.New(io.Discard, "", log.Ldate|log.Ltime|log.Lmicroseconds)

func initLogger(path string) {
	if strings.TrimSpace(path) == "" {
		logger = log.New(os.Stderr, "[GoHunt] ", log.Ldate|log.Ltime|log.Lmicroseconds)
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		logger = log.New(os.Stderr, "[GoHunt] ", log.Ldate|log.Ltime|log.Lmicroseconds)
		logger.Printf("log dosyası açılamadı: %v", err)
		return
	}
	mw := io.MultiWriter(os.Stderr, f)
	logger = log.New(mw, "[GoHunt] ", log.Ldate|log.Ltime|log.Lmicroseconds)
}

// HTTP hız limitleyici
var httpPermitCh chan struct{}
var osintPermitCh chan struct{}

func initRateLimiter(rate int) {
	if rate <= 0 {
		httpPermitCh = nil
		return
	}
	ch := make(chan struct{}, rate)
	ticker := time.NewTicker(time.Second / time.Duration(rate))
	go func() {
		for range ticker.C {
			select {
			case ch <- struct{}{}:
			default:
			}
		}
	}()
	httpPermitCh = ch
}

func initOsintRateLimiter(rate int) {
	if rate <= 0 {
		osintPermitCh = nil
		return
	}
	ch := make(chan struct{}, rate)
	ticker := time.NewTicker(time.Second / time.Duration(rate))
	go func() {
		for range ticker.C {
			select {
			case ch <- struct{}{}:
			default:
			}
		}
	}()
	osintPermitCh = ch
}

// Subdomain tarama (DNS brute force)
func scanSubdomains(target string) ([]SubdomainStatus, []string) {
	var errorsOut []string

	// Wordlist
	var candidates []string
	if strings.TrimSpace(subWordlistPath) != "" {
		// Özel wordlist kullan
		if listFromFile, err := readLinesLimited(subWordlistPath, 20000); err == nil {
			candidates = listFromFile
			logger.Printf("Using custom wordlist: %s (%d lines)", subWordlistPath, len(candidates))
		} else {
			errorsOut = append(errorsOut, fmt.Sprintf("Subdomain wordlist could not be read: %v", err))
			logger.Printf("sub-wordlist could not be read: %v", err)
			// Fallback to default wordlist on error
			candidates = defaultSubdomains()
		}
	} else {
		// Use default wordlist
		candidates = defaultSubdomains()
		logger.Printf("Using default wordlist (%d lines)", len(candidates))
	}

	resolver := &net.Resolver{}
	type item struct {
		name     string
		original string
	}
	jobs := make(chan item, len(candidates))
	var wg sync.WaitGroup
	var mu sync.Mutex
	var found []string
	var results []SubdomainStatus
	total := int64(len(candidates))
	var done int64

	worker := func() {
		defer wg.Done()
		for j := range jobs {
			var addrs []string
			err := withRetry(func() error {
				ctx, cancel := context.WithTimeout(context.Background(), subTimeout)
				defer cancel()
				a, e := resolver.LookupHost(ctx, j.name)
				if e != nil {
					return e
				}
				addrs = a
				return nil
			})

			mu.Lock()
			if err == nil && len(addrs) > 0 {
				found = append(found, j.name)
				results = append(results, SubdomainStatus{Name: j.original, Status: "Active"})
			} else {
				results = append(results, SubdomainStatus{Name: j.original, Status: "Not Found"})
			}
			mu.Unlock()

			atomic.AddInt64(&done, 1)
		}
	}

	// Start workers
	if subConcurrency <= 0 {
		subConcurrency = 100
	}
	wg.Add(subConcurrency)
	for i := 0; i < subConcurrency; i++ {
		go worker()
	}

	// Feed jobs
	go func() {
		for _, s := range candidates {
			fqdn := s + "." + target
			jobs <- item{name: fqdn, original: s}
		}
		close(jobs)
	}()

	wg.Wait()

	// Sonuçları sırala
	sort.Slice(results, func(i, j int) bool {
		return results[i].Name < results[j].Name
	})

	// OSINT kaynakları (sadece özel wordlist kullanılmadığında)
	if enableOSINT && strings.TrimSpace(subWordlistPath) == "" {
		logger.Printf("Collecting subdomains from OSINT sources...")
		// Sadece HackerTarget kullan (daha güvenilir)
		if subs, err := hackerTargetSubdomains(target); err == nil {
			// OSINT'ten gelen subdomain'leri "Active" olarak ekle
			for _, sub := range subs {
				// Zaten var mı kontrol et
				found := false
				for _, existing := range results {
					if existing.Name == sub {
						found = true
						break
					}
				}
				if !found {
					results = append(results, SubdomainStatus{Name: sub, Status: "Active"})
				}
			}
			logger.Printf("Added %d subdomains from OSINT", len(subs))
		} else {
			errorsOut = append(errorsOut, "HackerTarget error: "+err.Error())
			logger.Printf("HackerTarget error: %v", err)
		}

		// Tekrar sırala
		sort.Slice(results, func(i, j int) bool {
			return results[i].Name < results[j].Name
		})

		if osintMaxResults > 0 && len(results) > osintMaxResults {
			logger.Printf("OSINT subdomain list limited to %d (total: %d)", osintMaxResults, len(results))
			results = results[:osintMaxResults]
		}
	} else if enableOSINT && strings.TrimSpace(subWordlistPath) != "" {
		logger.Printf("Skipped OSINT sources due to custom wordlist usage")
	}

	if showProgress {
		logger.Printf("Subdomain scan completed: %d/%d", done, total)
	}

	return results, errorsOut
}

// Port tarama (TCP connect + banner grabbing)
func scanPorts(target string) ([]PortInfo, []string) {
	var errorsOut []string

	portList, err := parsePorts(portsArg)
	if err != nil {
		errorsOut = append(errorsOut, fmt.Sprintf("Port listesi hatalı: %v", err))
		return nil, errorsOut
	}

	type job struct{ port int }
	jobs := make(chan job, len(portList))
	var wg sync.WaitGroup
	var mu sync.Mutex
	var results []PortInfo
	var scanned int64

	if portConcurrency <= 0 {
		c := runtime.NumCPU()
		if c < 1 {
			c = 1
		}
		portConcurrency = minInt(400, maxInt(100, c*100))
	}

	worker := func() {
		defer wg.Done()
		for j := range jobs {
			addr := net.JoinHostPort(target, strconv.Itoa(j.port))
			var conn net.Conn
			err := withRetry(func() error {
				d := net.Dialer{Timeout: portTimeout}
				c, e := d.Dial("tcp", addr)
				if e != nil {
					return e
				}
				conn = c
				return nil
			})
			if err != nil {
				atomic.AddInt64(&scanned, 1)
				continue
			}
			_ = conn.SetDeadline(time.Now().Add(1500 * time.Millisecond))

			service := guessServiceByPort(j.port)
			banner := ""

			// Grab banners (daha hızlı)
			switch j.port {
			case 80, 8080, 8000:
				_, _ = conn.Write([]byte("HEAD / HTTP/1.0\r\nHost: " + target + "\r\n\r\n"))
				banner = readFirstLine(conn)
			case 443, 8443:
				// TLS handshake then HEAD
				tlsConn := tls.Client(conn, &tls.Config{ServerName: target, InsecureSkipVerify: true})
				if err := tlsConn.Handshake(); err == nil {
					_, _ = tlsConn.Write([]byte("HEAD / HTTP/1.0\r\nHost: " + target + "\r\n\r\n"))
					banner = readFirstLine(tlsConn)
				}
			case 22:
				banner = readFirstLine(conn)
			default:
				banner = readFirstLine(conn)
			}
			_ = conn.Close()

			mu.Lock()
			results = append(results, PortInfo{Port: j.port, Service: service, Banner: strings.TrimSpace(banner)})
			mu.Unlock()

			atomic.AddInt64(&scanned, 1)
		}
	}

	wg.Add(portConcurrency)
	for i := 0; i < portConcurrency; i++ {
		go worker()
	}
	go func() {
		for _, p := range portList {
			jobs <- job{port: p}
		}
		close(jobs)
	}()
	wg.Wait()

	sort.Slice(results, func(i, j int) bool { return results[i].Port < results[j].Port })

	return results, errorsOut
}

// Banner analiz + CVE arama (CIRCL API denemesi, başarısız olursa basit eşleme)
func scanCVEs(ports []PortInfo) ([]CVEInfo, []string) {
	var out []CVEInfo
	var errorsOut []string
	seen := map[string]bool{}

	for _, p := range ports {
		vendor, product, version := parseSoftwareFromBanner(p)
		if vendor == "" && product == "" {
			continue
		}
		q := vendor + "/" + product
		cves, err := fetchCVEsFromCircl(q, 5)
		if err != nil {
			// Fallback: simple heuristics
			if v := fallbackCVEs(vendor, product, version); len(v) > 0 {
				cves = v
			} else {
				errorsOut = append(errorsOut, fmt.Sprintf("Error while searching CVEs (%s): %v", q, err))
				logger.Printf("CVE API error (%s): %v", q, err)
			}
		}
		for _, c := range cves {
			if !seen[c.ID] {
				out = append(out, c)
				seen[c.ID] = true
			}
		}
	}
	return out, errorsOut
}

// Web teknolojileri tespiti (HTTP başlık/HTML analiz)
func detectWebTechs(baseURL string) ([]string, []string) {
	var errorsOut []string
	var techs []string
	if baseURL == "" {
		return techs, errorsOut
	}
	body, hdrs, err := httpFetch(baseURL)
	if err != nil {
		errorsOut = append(errorsOut, fmt.Sprintf("Web analysis error: %v", err))
		logger.Printf("web analysis error: %v", err)
		return techs, errorsOut
	}

	// HTTP Headers'dan teknoloji tespiti
	if srv := hdrs.Get("Server"); srv != "" {
		techs = append(techs, "Server: "+srv)
	}
	if xp := hdrs.Get("X-Powered-By"); xp != "" {
		techs = append(techs, "X-Powered-By: "+xp)
	}
	if cf := hdrs.Get("CF-RAY"); cf != "" {
		techs = append(techs, "Cloudflare CDN")
	}
	if cf := hdrs.Get("Server"); cf != "" && strings.Contains(strings.ToLower(cf), "cloudflare") {
		techs = append(techs, "Cloudflare")
	}

	// HTML içeriğinden teknoloji tespiti
	bodyLower := strings.ToLower(body)

	// JavaScript Frameworks
	if strings.Contains(bodyLower, "react") || strings.Contains(bodyLower, "reactjs") {
		techs = append(techs, "React.js")
	}
	if strings.Contains(bodyLower, "vue") || strings.Contains(bodyLower, "vuejs") {
		techs = append(techs, "Vue.js")
	}
	if strings.Contains(bodyLower, "angular") {
		techs = append(techs, "Angular")
	}
	if strings.Contains(bodyLower, "jquery") {
		techs = append(techs, "jQuery")
	}

	// CMS Systems
	if strings.Contains(bodyLower, "wp-content") || strings.Contains(bodyLower, "wordpress") {
		techs = append(techs, "WordPress")
	}
	if strings.Contains(bodyLower, "drupal") {
		techs = append(techs, "Drupal")
	}
	if strings.Contains(bodyLower, "joomla") {
		techs = append(techs, "Joomla")
	}

	// Web Servers
	if strings.Contains(bodyLower, "apache") {
		techs = append(techs, "Apache")
	}
	if strings.Contains(bodyLower, "nginx") {
		techs = append(techs, "Nginx")
	}

	// Analytics & Tracking
	if strings.Contains(bodyLower, "google-analytics") || strings.Contains(bodyLower, "gtag") {
		techs = append(techs, "Google Analytics")
	}
	if strings.Contains(bodyLower, "facebook") && strings.Contains(bodyLower, "pixel") {
		techs = append(techs, "Facebook Pixel")
	}

	// CDN & Cloud Services
	if strings.Contains(bodyLower, "cloudflare") {
		techs = append(techs, "Cloudflare")
	}
	if strings.Contains(bodyLower, "aws") || strings.Contains(bodyLower, "amazon") {
		techs = append(techs, "Amazon Web Services")
	}

	// Eğer hiç teknoloji bulunamazsa
	if len(techs) == 0 {
		techs = append(techs, "Standard Web Technologies")
	}

	return techs, errorsOut
}

// Reverse IP: hedefin IP'sini çöz ve PTR'ı getir
func reverseIP(target string) (string, []string) {
	var errorsOut []string
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var addrs []net.IPAddr
	err := withRetry(func() error {
		a, e := net.DefaultResolver.LookupIPAddr(ctx, target)
		if e != nil {
			return e
		}
		addrs = a
		return nil
	})
	if err != nil || len(addrs) == 0 {
		if err != nil {
			errorsOut = append(errorsOut, fmt.Sprintf("IP could not be resolved: %v", err))
			logger.Printf("IP could not be resolved: %v", err)
		}
		return "", errorsOut
	}
	ip := addrs[0].IP.String()
	return ip, errorsOut
}

// WHOIS (basit): .com/.net için verisign, .org için pir; diğerleri iana yönlendirmesi yapılmaz, sadece basit deneme
func whoisLookup(target string) (string, []string) {
	var errorsOut []string
	host := whoisServerForHost(target)
	if host == "" {
		return "", nil
	}
	var conn net.Conn
	err := withRetry(func() error {
		c, e := net.DialTimeout("tcp", net.JoinHostPort(host, "43"), 4*time.Second)
		if e != nil {
			return e
		}
		conn = c
		return nil
	})
	if err != nil {
		logger.Printf("WHOIS connection error: %v", err)
		return "", []string{fmt.Sprintf("WHOIS connection error: %v", err)}
	}
	defer conn.Close()
	_, _ = conn.Write([]byte(target + "\r\n"))
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	data, _ := io.ReadAll(conn)
	out := string(data)
	// Kısa özet döndür
	lines := strings.Split(out, "\n")
	keep := []string{}
	for _, ln := range lines {
		if strings.Contains(strings.ToLower(ln), "registrar") || strings.Contains(strings.ToLower(ln), "name server") || strings.Contains(strings.ToLower(ln), "creation date") {
			keep = append(keep, ln)
		}
		if len(keep) >= 12 {
			break
		}
	}
	if len(keep) == 0 {
		keep = append(keep, strings.TrimSpace(lines[0]))
	}
	return strings.Join(keep, "\n"), errorsOut
}

// Basit XSS, SQLi, LFI testleri (otomatik)
func vulnTests(baseURL string) ([]string, []string) {
	var errorsOut []string
	if baseURL == "" {
		return nil, nil
	}
	results := []string{}

	// XSS Reflected/DOM payloadları
	xssPayloads := []string{
		"<script>alert(1)</script>", "\"'><img src=x onerror=alert(1)>", "</script><script>alert(1)</script>",
		"<svg/onload=alert(1)>", "<img src=x onerror=confirm(1)>",
	}
	tested := false
	for _, p := range xssPayloads {
		if body, _, err := httpFetch(addParam(baseURL, "q", p)); err == nil {
			tested = true
			if strings.Contains(body, p) {
				results = append(results, "XSS: Possible reflected XSS (payload echoed)")
				break
			}
		}
	}
	if !tested {
		errorsOut = append(errorsOut, "XSS test: request failed")
	} else if len(results) == 0 {
		results = append(results, "XSS: No indication")
	}

	// SQLi klasik ve varyasyonlar
	sqliPayloads := []string{"1' OR '1'='1", "' OR '1'='1' -- ", "\") OR (\"1\"=\"1", "1;WAITFOR DELAY '0:0:1'--"}
	tested = false
	for _, p := range sqliPayloads {
		if body, _, err := httpFetch(addParam(baseURL, "id", p)); err == nil {
			tested = true
			if looksLikeSQLError(body) {
				results = append(results, "SQLi: Possible error-based SQLi")
				break
			}
		}
	}
	if !tested {
		errorsOut = append(errorsOut, "SQLi test: request failed")
	} else if !containsPrefix(results, "SQLi:") {
		results = append(results, "SQLi: No indication")
	}

	// LFI Linux/Windows patikaları
	lfiPayloads := []string{"../../../../etc/passwd", "..\\..\\..\\..\\windows\\win.ini", "../../../../proc/self/environ"}
	// RFI denemesi (eğer uygulama dış URL kabul ediyorsa)
	rfiURL := addParam(baseURL, "file", "http://example.com")
	_, _, _ = httpFetch(rfiURL)
	// Basit SSTI belirtisi (template yansıması)
	sstiPayload := "{{7*7}}"
	if body, _, err := httpFetch(addParam(baseURL, "q", sstiPayload)); err == nil {
		if strings.Contains(body, "49") {
			results = append(results, "SSTI: Possible template injection")
		}
	}
	// Basit Open Redirect denemesi
	if _, _, err := httpFetch(addParam(baseURL, "next", "//evil.com")); err == nil {
		// Tespit etmek zor; sadece isteği yapıyoruz
	}
	tested = false
	for _, p := range lfiPayloads {
		if body, _, err := httpFetch(addParam(baseURL, "file", p)); err == nil {
			tested = true
			if strings.Contains(body, "root:x:0:0:") || strings.Contains(strings.ToLower(body), "[fonts]") {
				results = append(results, "LFI: Possible Local File Inclusion")
				break
			}
		}
	}
	if !tested {
		errorsOut = append(errorsOut, "LFI test: request failed")
	} else if !containsPrefix(results, "LFI:") {
		results = append(results, "LFI: No indication")
	}
	return results, errorsOut
}

// Paralel tarama örneği
func parallelScan(target string, doSub, doPort, doCVE, doTech, doRev, doWhois, doVuln bool) ScanResult {
	result := ScanResult{Target: target}
	var errs []string
	var warns []string
	var errMu sync.Mutex
	var warnMu sync.Mutex

	// Progress messages will be shown in the final report, not during scan

	// Faz 1: Subdomain, Port, ReverseIP, WHOIS
	var wg sync.WaitGroup
	activeGoroutines := 0

	if doSub {
		wg.Add(1)
		activeGoroutines++
		go func() {
			defer wg.Done()
			subs, errList := scanSubdomains(target)
			result.Subdomains = subs
			if len(errList) > 0 {
				errMu.Lock()
				errs = append(errs, errList...)
				errMu.Unlock()
			}
		}()
	}

	if doPort {
		wg.Add(1)
		activeGoroutines++
		go func() {
			defer wg.Done()
			if scanMode == "syn" {
				warnMu.Lock()
				warns = append(warns, "SYN scan is not supported in this version; falling back to connect mode")
				warnMu.Unlock()
				logger.Printf("SYN scan is not supported; falling back to connect mode")
			}
			ports, errList := scanPorts(target)
			result.OpenPorts = ports
			if len(errList) > 0 {
				errMu.Lock()
				errs = append(errs, errList...)
				errMu.Unlock()
			}
		}()
	}

	if doRev {
		wg.Add(1)
		activeGoroutines++
		go func() {
			defer wg.Done()
			ip, errList := reverseIP(target)
			result.ResolvedIP = ip
			if len(errList) > 0 {
				errMu.Lock()
				errs = append(errs, errList...)
				errMu.Unlock()
			}
		}()
	}

	if doWhois {
		wg.Add(1)
		activeGoroutines++
		go func() {
			defer wg.Done()
			w, errList := whoisLookup(target)
			result.Whois = w
			if len(errList) > 0 {
				errMu.Lock()
				errs = append(errs, errList...)
				errMu.Unlock()
			}
		}()
	}

	if activeGoroutines > 0 {
		wg.Wait()
	}

	// Base URL belirle
	baseURL := chooseBaseURL(target, result.OpenPorts)

	// Faz 2: CVE, WebTech, VulnTests
	if doCVE {
		cves, errList := scanCVEs(result.OpenPorts)
		result.CVEs = cves
		if len(errList) > 0 {
			errMu.Lock()
			errs = append(errs, errList...)
			errMu.Unlock()
		}
	}

	if doTech {
		techs, errList := detectWebTechs(baseURL)
		result.WebTechs = techs
		if len(errList) > 0 {
			errMu.Lock()
			errs = append(errs, errList...)
			errMu.Unlock()
		}
	}

	if doVuln {
		tests, errList := vulnTests(baseURL)
		result.VulnResults = tests
		if len(errList) > 0 {
			errMu.Lock()
			errs = append(errs, errList...)
			errMu.Unlock()
		}
	}

	result.Errors = errs
	result.Warnings = warns

	return result
}

// Rapor çıktısı (modern format)
func printReport(res ScanResult, verbose bool, doSub, doPort, doCVE, doTech, doRev, doWhois, doVuln bool) {
	fmt.Println("=" + strings.Repeat("=", 70) + "=")
	fmt.Printf("🎯 TARGET: %s\n", bold(cyan(res.Target)))
	fmt.Println("=" + strings.Repeat("=", 70) + "=")
	fmt.Println()

	if doSub {
		// Sadece aktif subdomain'leri filtrele
		var activeSubdomains []SubdomainStatus
		for _, s := range res.Subdomains {
			if s.Status == "Active" {
				activeSubdomains = append(activeSubdomains, s)
			}
		}

		if len(activeSubdomains) > 0 {
			fmt.Printf("📡 SUBDOMAIN SCAN (%d active)\n", len(activeSubdomains))
			fmt.Println(strings.Repeat("-", 72))

			// İlk 15 aktif subdomain'i göster
			displayLimit := 15
			subsToShow := activeSubdomains
			if len(subsToShow) > displayLimit {
				subsToShow = subsToShow[:displayLimit]
			}

			for _, s := range subsToShow {
				fmt.Printf("  %s %s\n", green("✓"), truncateString(s.Name, 65))
			}

			if len(activeSubdomains) > displayLimit {
				fmt.Printf("  ... and %d more active subdomains\n", len(activeSubdomains)-displayLimit)
			}
		} else {
			fmt.Printf("📡 SUBDOMAIN SCAN\n")
			fmt.Println(strings.Repeat("-", 72))
			fmt.Printf("  No active subdomains found\n")
		}
		fmt.Println()
	}
	if doPort {
		if len(res.OpenPorts) > 0 {
			fmt.Printf("🔌 PORT SCAN (%d open ports)\n", len(res.OpenPorts))
			fmt.Println(strings.Repeat("-", 72))
			fmt.Printf("  %-8s  %-15s  %-35s\n", "PORT", "SERVICE", "BANNER")
			fmt.Println(strings.Repeat("-", 72))

			for _, p := range res.OpenPorts {
				banner := truncateString(p.Banner, 35)
				if banner == "" {
					banner = "N/A"
				}
				fmt.Printf("  %-8s  %-15s  %s\n",
					cyan(strconv.Itoa(p.Port)+"/tcp"),
					yellow(p.Service),
					banner)
			}
		} else {
			fmt.Printf("🔌 PORT SCAN\n")
			fmt.Println(strings.Repeat("-", 72))
			fmt.Printf("  No results\n")
		}
		fmt.Println()
	}
	if doCVE {
		if len(res.CVEs) > 0 {
			fmt.Printf("⚠️  CVE SCAN (%d found)\n", len(res.CVEs))
			fmt.Println(strings.Repeat("-", 72))
			fmt.Printf("  %-15s  %-8s  %-35s  %-12s\n", "CVE ID", "SEVERITY", "DESCRIPTION", "CVSS")
			fmt.Println(strings.Repeat("-", 72))

			for _, c := range res.CVEs {
				severityColor := ""
				if c.Severity == "Kritik" {
					severityColor = red("Critical")
				} else if c.Severity == "Yüksek" {
					severityColor = yellow("High")
				} else if c.Severity == "Orta" {
					severityColor = "Medium"
				} else if c.Severity == "Düşük" {
					severityColor = "Low"
				} else {
					severityColor = c.Severity
				}

				desc := truncateString(c.Description, 35)
				if desc == "" {
					desc = "N/A"
				}

				fmt.Printf("  %-15s  %-8s  %-35s  %s\n",
					cyan(c.ID),
					severityColor,
					desc,
					cyan(fmt.Sprintf("CVSS: %.1f", c.CVSS)))

				if verbose {
					fmt.Printf("  %-15s  Source: %s\n",
						"", truncateString(c.Source, 50))
				}
			}
		} else {
			fmt.Printf("⚠️  CVE SCAN\n")
			fmt.Println(strings.Repeat("-", 72))
			fmt.Printf("  No CVEs found\n")
		}
		fmt.Println()
	}
	if doTech {
		if len(res.WebTechs) > 0 {
			fmt.Printf("🚀 WEB TECHNOLOGY DETECTION (%d technologies)\n", len(res.WebTechs))
			fmt.Println(strings.Repeat("-", 72))

			// Teknolojileri 3 sütunda göster
			cols := 3
			for i := 0; i < len(res.WebTechs); i += cols {
				line := "  "
				for j := 0; j < cols && i+j < len(res.WebTechs); j++ {
					tech := truncateString(res.WebTechs[i+j], 20)
					line += fmt.Sprintf("%-20s ", cyan(tech))
				}
				fmt.Println(line)
			}
		} else {
			fmt.Printf("🚀 WEB TECHNOLOGY DETECTION\n")
			fmt.Println(strings.Repeat("-", 72))
			fmt.Printf("  No results\n")
		}
		fmt.Println()
	}
	if doRev {
		if res.ResolvedIP != "" {
			fmt.Printf("🌐 IP INFORMATION\n")
			fmt.Println(strings.Repeat("-", 72))
			fmt.Printf("  IP Address: %s\n", cyan(res.ResolvedIP))
		} else {
			fmt.Printf("🌐 IP INFORMATION\n")
			fmt.Println(strings.Repeat("-", 72))
			fmt.Printf("  No results\n")
		}
		fmt.Println()
	}
	if doWhois {
		if res.Whois != "" {
			fmt.Printf("📋 WHOIS INFORMATION\n")
			fmt.Println(strings.Repeat("-", 72))
			whoisLines := strings.Split(res.Whois, "\n")
			for _, line := range whoisLines {
				if strings.TrimSpace(line) != "" {
					fmt.Printf("  %s\n", truncateString(line, 70))
				}
			}
		} else {
			fmt.Printf("📋 WHOIS INFORMATION\n")
			fmt.Println(strings.Repeat("-", 72))
			fmt.Printf("  No results\n")
		}
		fmt.Println()
	}
	if doVuln {
		if len(res.VulnResults) > 0 {
			fmt.Printf("🔒 VULNERABILITY TESTS (%d tests)\n", len(res.VulnResults))
			fmt.Println(strings.Repeat("-", 72))

			for _, v := range res.VulnResults {
				status := ""
				if strings.Contains(v, "No indication") {
					status = green("SAFE")
				} else if strings.Contains(v, "Possible") {
					status = yellow("WARN")
				} else {
					status = "TEST"
				}

				desc := truncateString(v, 65)
				fmt.Printf("  [%-8s] %s\n", status, desc)
			}
		} else {
			fmt.Printf("🔒 VULNERABILITY TESTS\n")
			fmt.Println(strings.Repeat("-", 72))
			fmt.Printf("  No results\n")
		}
		fmt.Println()
	}
	if len(res.Warnings) > 0 && verbose {
		fmt.Printf("⚠️  WARNINGS (%d)\n", len(res.Warnings))
		fmt.Println(strings.Repeat("-", 72))
		for _, w := range res.Warnings {
			fmt.Printf("  %s %s\n", yellow("⚠"), truncateString(w, 70))
		}
		fmt.Println()
	}
	if len(res.Errors) > 0 {
		fmt.Printf("❌ ERRORS (%d)\n", len(res.Errors))
		fmt.Println(strings.Repeat("-", 72))
		for _, e := range res.Errors {
			fmt.Printf("  %s %s\n", red("✗"), truncateString(e, 70))
		}
		fmt.Println()
	}
}

// JSON çıktı
func writeJSON(res ScanResult, filename string) error {
	data, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0644)
}

// HTML çıktı (basit örnek)
func writeHTML(res ScanResult, filename string) error {
	html := "<html><head><title>GoHunt Report</title></head><body>"
	html += fmt.Sprintf("<h1>GoHunt Report - %s</h1>", res.Target)
	html += "<h2>Subdomains</h2><ul>"
	for _, s := range res.Subdomains {
		html += "<li>" + s.Name + " (" + s.Status + ")</li>"
	}
	html += "</ul><h2>Open Ports</h2><ul>"
	for _, p := range res.OpenPorts {
		html += fmt.Sprintf("<li>%d/tcp - %s (%s)</li>", p.Port, p.Service, p.Banner)
	}
	html += "</ul><h2>Discovered CVEs</h2><ul>"
	for _, c := range res.CVEs {
		html += fmt.Sprintf("<li>%s (%s) - %s</li>", c.ID, c.Description, c.Severity)
	}
	html += "</ul><h2>Web Technologies</h2><ul>"
	for _, t := range res.WebTechs {
		html += "<li>" + t + "</li>"
	}
	html += "</ul></body></html>"
	return os.WriteFile(filename, []byte(html), 0644)
}

func main() {
	// Komut satırı argümanları
	target := flag.String("target", "", "Target domain or IP")
	cveScan := flag.Bool("cve-scan", false, "Run CVE scan")
	output := flag.String("output", "", "Output file (json/html/csv/xml/txt)")
	portScan := flag.Bool("port-scan", false, "Run port scan")
	subdomain := flag.Bool("subdomain", false, "Run subdomain scan")
	reverseIP := flag.Bool("reverse-ip", false, "Run reverse IP lookup")
	whois := flag.Bool("whois", false, "Run WHOIS lookup")
	xss := flag.Bool("xss", false, "Run XSS test")
	sqli := flag.Bool("sqli", false, "Run SQLi test")
	lfi := flag.Bool("lfi", false, "Run LFI test")
	verbose := flag.Bool("verbose", false, "Verbose output")
	help := flag.Bool("h", false, "Show usage")
	allInOne := flag.Bool("all-in-one", false, "Run all scans (default if none selected)")

	// Gelişmiş parametreler
	flag.StringVar(&portsArg, "ports", "22,21,25,53,80,110,143,443,587,993,995,3306,5432,6379,8080,8443", "Ports to scan (comma or range: 1-1024)")
	var portTimeoutMs int
	flag.IntVar(&portTimeoutMs, "port-timeout-ms", 800, "Port connect timeout (ms)")
	flag.IntVar(&portConcurrency, "port-concurrency", 200, "Port scan concurrency")
	flag.StringVar(&subWordlistPath, "sub-wordlist", "", "Subdomain wordlist file (optional)")
	var subTimeoutMs int
	flag.IntVar(&subTimeoutMs, "sub-timeout-ms", 1200, "Subdomain DNS timeout (ms)")
	flag.IntVar(&subConcurrency, "sub-concurrency", 150, "Subdomain scan concurrency")
	var httpTimeoutMs int
	flag.IntVar(&httpTimeoutMs, "http-timeout-ms", 4000, "HTTP request timeout (ms)")
	flag.StringVar(&schemeMode, "scheme", "auto", "Protocol: auto|http|https")
	flag.StringVar(&logFilePath, "log-file", "", "Log file (default stderr)")
	flag.IntVar(&retries, "retries", 2, "Retry count for failed requests")
	var retryBackoffMs int
	flag.IntVar(&retryBackoffMs, "retry-backoff-ms", 250, "Backoff between retries (ms)")
	flag.StringVar(&scanMode, "scan-mode", "connect", "Port scan mode: connect|syn")
	flag.BoolVar(&enableOSINT, "osint", true, "Collect subdomains from OSINT sources")
	flag.BoolVar(&showProgress, "progress", true, "Log scan progress")
	flag.IntVar(&rateLimitPerSec, "rate-limit-ps", 3, "Global HTTP rate limit (request/s)")
	flag.IntVar(&osintMaxResults, "osint-max", 5000, "Max subdomains to collect via OSINT")
	flag.BoolVar(&insecureTLS, "insecure-tls", false, "Disable TLS certificate verification (not recommended)")
	flag.StringVar(&caFile, "ca-file", "", "Custom CA certificate file (PEM)")
	var osintTimeoutMs int
	flag.IntVar(&osintTimeoutMs, "osint-timeout-ms", 10000, "OSINT request timeout (ms)")
	flag.IntVar(&osintRetries, "osint-retries", 3, "OSINT retry count")
	var osintBackoffMs int
	flag.IntVar(&osintBackoffMs, "osint-backoff-ms", 750, "OSINT retry backoff (ms)")
	flag.IntVar(&osintRateLimit, "osint-rate-limit-ps", 1, "OSINT HTTP rate limit (request/s)")

	flag.Parse()

	if *help || *target == "" {
		printUsage()
		os.Exit(0)
	}

	// logger
	initLogger(logFilePath)
	// CA havuzu
	if strings.TrimSpace(caFile) != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			logger.Printf("CA dosyası okunamadı: %v", err)
		} else {
			caPool = x509.NewCertPool()
			if ok := caPool.AppendCertsFromPEM(pem); !ok {
				logger.Printf("CA dosyası PEM yüklenemedi")
			}
		}
	}

	printBanner()
	start := time.Now()
	fmt.Printf("Scan Start: %s\n", start.Format("2006-01-02 15:04:05"))

	// Süre dönüşümleri
	portTimeout = time.Duration(portTimeoutMs) * time.Millisecond
	subTimeout = time.Duration(subTimeoutMs) * time.Millisecond
	httpTimeout = time.Duration(httpTimeoutMs) * time.Millisecond
	retryBackoff = time.Duration(retryBackoffMs) * time.Millisecond
	initRateLimiter(rateLimitPerSec)
	osintTimeout = time.Duration(osintTimeoutMs) * time.Millisecond
	osintBackoff = time.Duration(osintBackoffMs) * time.Millisecond
	initOsintRateLimiter(osintRateLimit)

	// Hangi testler yapılacak?
	doSub := *subdomain
	doPort := *portScan
	doCVE := *cveScan
	doTech := true // Web teknolojileri her zaman tespit edilsin
	doRev := *reverseIP
	doWhois := *whois
	doVuln := *xss || *sqli || *lfi

	// all-in-one veya hiçbir bayrak yoksa hepsini aç
	noneSelected := !(doSub || doPort || doCVE || doRev || doWhois || doVuln)
	if *allInOne || noneSelected {
		doSub = true
		doPort = true
		doCVE = true
		doRev = true
		doWhois = true
		doVuln = true
	}

	// Hızlı tarama için timeout'ları kısalt
	if *allInOne || noneSelected {
		httpTimeout = 6 * time.Second
		osintTimeout = 8 * time.Second
		portTimeout = 300 * time.Millisecond
		subTimeout = 500 * time.Millisecond
		retries = 1
		osintRetries = 1
		// Hızlı tarama için concurrency artır
		if portConcurrency < 500 {
			portConcurrency = 500
		}
		if subConcurrency < 300 {
			subConcurrency = 300
		}
		// OSINT'i hızlandır
		if osintRateLimit < 3 {
			osintRateLimit = 3
		}
	}

	// Genel timeout ile tarama
	scanCtx, scanCancel := context.WithTimeout(context.Background(), 2*time.Minute+15*time.Second)
	defer scanCancel()

	// Tarama sonucunu channel üzerinden al
	resultChan := make(chan ScanResult, 1)
	go func() {
		result := parallelScan(*target, doSub, doPort, doCVE, doTech, doRev, doWhois, doVuln)
		result.ScanStart = start.Format("2006-01-02 15:04:05")
		result.ScanDuration = time.Since(start).String()
		resultChan <- result
	}()

	// Wait for timeout or result
	var result ScanResult
	select {
	case result = <-resultChan:
		// Completed normally
	case <-scanCtx.Done():
		// Timeout - show partial results
		fmt.Println(red("⚠️  Scan timed out! Showing partial results..."))
		result = ScanResult{
			Target:       *target,
			ScanStart:    start.Format("2006-01-02 15:04:05"),
			ScanDuration: time.Since(start).String(),
			Errors:       []string{"Scan timed out (2m15s)"},
			Warnings:     []string{"Some scans did not complete"},
		}
	}

	// Çıktı dosyası
	if *output != "" {
		if strings.HasSuffix(*output, ".json") {
			if err := writeJSON(result, *output); err != nil {
				fmt.Println(red("Failed to write JSON output:"), err)
				logger.Printf("json output error: %v", err)
			} else {
				fmt.Println(green("JSON output saved:"), *output)
			}
		} else if strings.HasSuffix(*output, ".html") {
			if err := writeHTML(result, *output); err != nil {
				fmt.Println(red("Failed to write HTML output:"), err)
				logger.Printf("html output error: %v", err)
			} else {
				fmt.Println(green("HTML output saved:"), *output)
			}
		} else if strings.HasSuffix(*output, ".csv") {
			if err := writeCSV(result, *output); err != nil {
				fmt.Println(red("Failed to write CSV output:"), err)
				logger.Printf("csv output error: %v", err)
			} else {
				fmt.Println(green("CSV output saved:"), *output)
			}
		} else if strings.HasSuffix(*output, ".xml") {
			if err := writeXML(result, *output); err != nil {
				fmt.Println(red("Failed to write XML output:"), err)
				logger.Printf("xml output error: %v", err)
			} else {
				fmt.Println(green("XML output saved:"), *output)
			}
		} else if strings.HasSuffix(*output, ".txt") {
			if err := writeTXT(result, *output); err != nil {
				fmt.Println(red("Failed to write TXT output:"), err)
				logger.Printf("txt output error: %v", err)
			} else {
				fmt.Println(green("TXT output saved:"), *output)
			}
		} else {
			fmt.Println(yellow("Unknown output format; printed to console only."))
		}
	}

	// Rapor çıktısı (EXAMPLE.md formatında)
	printReport(result, *verbose, doSub, doPort, doCVE, doTech, doRev, doWhois, doVuln)

	// Özet
	fmt.Println("=" + strings.Repeat("=", 70) + "=")
	fmt.Printf("📊 SCAN SUMMARY\n")
	fmt.Println("=" + strings.Repeat("=", 70) + "=")
	fmt.Printf("🎯 Target: %s\n", bold(cyan(result.Target)))
	if doSub {
		// Sadece aktif subdomain sayısını göster
		activeCount := 0
		for _, s := range result.Subdomains {
			if s.Status == "Active" {
				activeCount++
			}
		}
		fmt.Printf("📡 Subdomains: %s\n", bold(strconv.Itoa(activeCount)))
	}
	if doPort {
		fmt.Printf("🔌 Open Ports: %s\n", bold(strconv.Itoa(len(result.OpenPorts))))
	}
	if doCVE {
		fmt.Printf("⚠️  CVEs: %s\n", bold(strconv.Itoa(len(result.CVEs))))
	}
	if doTech {
		fmt.Printf("🚀 Web Technologies: %s\n", bold(strconv.Itoa(len(result.WebTechs))))
	}
	if doVuln {
		fmt.Printf("🔒 Vulnerability Tests: %s\n", bold(strconv.Itoa(len(result.VulnResults))))
	}
	if doRev && result.ResolvedIP != "" {
		fmt.Printf("🌐 IP: %s\n", bold(cyan(result.ResolvedIP)))
	}
	if len(result.Errors) > 0 {
		fmt.Printf("❌ Errors: %s\n", bold(red(strconv.Itoa(len(result.Errors)))))
	}
	if len(result.Warnings) > 0 {
		fmt.Printf("⚠️  Warnings: %s\n", bold(yellow(strconv.Itoa(len(result.Warnings)))))
	}
	fmt.Printf("⏱️  Duration: %s\n", bold(result.ScanDuration))
	fmt.Println("=" + strings.Repeat("=", 70) + "=")
	fmt.Println()
	fmt.Println("© 2025 GoHunt - Developed by Mynex")
}

// ----------------- Yardımcı Fonksiyonlar -----------------

func defaultSubdomains() []string {
	return []string{
		"www", "mail", "dev", "test", "api", "blog", "staging", "admin", "ftp", "smtp", "vpn", "portal", "m", "mobile", "img", "cdn", "static", "beta", "old", "new", "ns1", "ns2", "shop", "app", "support", "help", "git", "jira", "grafana", "monitor", "status", "cache", "db", "node", "edge", "proxy", "gw", "gateway", "pay", "payment", "auth",
	}
}

func readLinesLimited(path string, limit int) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := []string{}
	s := bufio.NewScanner(f)
	for s.Scan() {
		ln := strings.TrimSpace(s.Text())
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		out = append(out, ln)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func parsePorts(spec string) ([]int, error) {
	if strings.TrimSpace(spec) == "" {
		return nil, errors.New("boş port listesi")
	}
	set := map[int]bool{}
	parts := strings.Split(spec, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if strings.Contains(p, "-") {
			rng := strings.SplitN(p, "-", 2)
			a, _ := strconv.Atoi(strings.TrimSpace(rng[0]))
			b, _ := strconv.Atoi(strings.TrimSpace(rng[1]))
			if a > 0 && b > 0 && a <= b {
				for i := a; i <= b; i++ {
					set[i] = true
				}
			}
		} else {
			v, err := strconv.Atoi(p)
			if err == nil && v > 0 {
				set[v] = true
			}
		}
	}
	out := make([]int, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Ints(out)
	return out, nil
}

func guessServiceByPort(p int) string {
	switch p {
	case 21:
		return "FTP"
	case 22:
		return "SSH"
	case 25:
		return "SMTP"
	case 53:
		return "DNS"
	case 80, 8080, 8000:
		return "HTTP"
	case 110:
		return "POP3"
	case 143:
		return "IMAP"
	case 443, 8443:
		return "HTTPS"
	case 3306:
		return "MySQL"
	case 5432:
		return "PostgreSQL"
	case 6379:
		return "Redis"
	default:
		return "tcp"
	}
}

func readFirstLine(r io.Reader) string {
	rd := bufio.NewReader(r)
	line, _ := rd.ReadString('\n')
	return line
}

func parseSoftwareFromBanner(p PortInfo) (vendor, product, version string) {
	b := p.Banner + " " + p.Service
	// Simple regexes
	if strings.Contains(strings.ToLower(b), "apache") {
		vendor, product = "apache", "http_server"
		if m := regexp.MustCompile(`Apache[/ ]([0-9.]+)`).FindStringSubmatch(b); len(m) == 2 {
			version = m[1]
		}
	} else if strings.Contains(strings.ToLower(b), "nginx") {
		vendor, product = "nginx", "nginx"
		if m := regexp.MustCompile(`nginx[/ ]([0-9.]+)`).FindStringSubmatch(b); len(m) == 2 {
			version = m[1]
		}
	} else if strings.Contains(strings.ToLower(b), "openssh") || p.Port == 22 {
		vendor, product = "openssh", "openssh"
		if m := regexp.MustCompile(`OpenSSH[_ ]([0-9p.]+)`).FindStringSubmatch(b); len(m) == 2 {
			version = m[1]
		}
	} else if strings.Contains(strings.ToLower(b), "mysql") || p.Port == 3306 {
		vendor, product = "oracle", "mysql"
	} else if strings.Contains(strings.ToLower(b), "postgresql") || p.Port == 5432 {
		vendor, product = "postgresql", "postgresql"
	}
	return
}

func fetchCVEsFromCircl(vendorProduct string, limit int) ([]CVEInfo, error) {
	// Endpoint: https://cve.circl.lu/api/search/vendor/product
	u := "https://cve.circl.lu/api/search/" + url.PathEscape(vendorProduct)
	client := &http.Client{Timeout: 6 * time.Second}
	resp, err := client.Get(u)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("CIRCL HTTP %d", resp.StatusCode)
	}
	var payload struct {
		Results []struct {
			ID         string   `json:"id"`
			Summary    string   `json:"summary"`
			CVSS       float64  `json:"cvss"`
			References []string `json:"references"`
		} `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	out := []CVEInfo{}
	for i, r := range payload.Results {
		if limit > 0 && i >= limit {
			break
		}
		ref := ""
		if len(r.References) > 0 {
			ref = r.References[0]
		}
		sev := "Medium"
		if r.CVSS >= 9 {
			sev = "Critical"
		} else if r.CVSS >= 7 {
			sev = "High"
		} else if r.CVSS >= 4 {
			sev = "Medium"
		} else {
			sev = "Low"
		}
		out = append(out, CVEInfo{ID: r.ID, Description: r.Summary, Severity: sev, Source: "CIRCL", ExploitLink: ref, CVSS: r.CVSS})
	}
	return out, nil
}

func fallbackCVEs(vendor, product, version string) []CVEInfo {
	// Basit eşleme: popüler servisler için örnekler
	if vendor == "apache" && product == "http_server" {
		return []CVEInfo{{ID: "CVE-2021-41773", Description: "Apache Path Traversal", Severity: "High", Source: "Heuristic", ExploitLink: "https://www.exploit-db.com/exploits/50406", CVSS: 7.5}}
	}
	if vendor == "nginx" {
		return []CVEInfo{}
	}
	if product == "openssh" {
		return []CVEInfo{}
	}
	return nil
}

func httpFetch(u string) (string, http.Header, error) {
	var body string
	var hdr http.Header
	err := withRetry(func() error {
		if httpPermitCh != nil {
			<-httpPermitCh
		}
		tlsCfg := &tls.Config{}
		if insecureTLS {
			tlsCfg.InsecureSkipVerify = true
		}
		if caPool != nil {
			tlsCfg.RootCAs = caPool
		}
		client := &http.Client{Timeout: httpTimeout, Transport: &http.Transport{TLSClientConfig: tlsCfg}}
		req, e := http.NewRequest("GET", u, nil)
		if e != nil {
			return e
		}
		req.Header.Set("User-Agent", "GoHunt/1.0")
		// context tabanlı timeout/iptal için
		ctx, cancel := context.WithTimeout(context.Background(), httpTimeout)
		defer cancel()
		req = req.WithContext(ctx)
		resp, e := client.Do(req)
		if e != nil {
			return e
		}
		defer resp.Body.Close()
		lr := io.LimitReader(resp.Body, 512*1024)
		b, e := io.ReadAll(lr)
		if e != nil {
			return e
		}
		body = string(b)
		hdr = resp.Header
		return nil
	})
	return body, hdr, err
}

func addParam(u, key, value string) string {
	parsed, err := url.Parse(u)
	if err != nil {
		return u
	}
	q := parsed.Query()
	q.Set(key, value)
	parsed.RawQuery = q.Encode()
	return parsed.String()
}

func looksLikeSQLError(body string) bool {
	patterns := []string{
		"You have an error in your SQL syntax",
		"warning: mysql",
		"unclosed quotation mark after the character string",
		"syntax error at or near",
		"SQLSTATE[",
		"ODBC",
		"ORA-00933",
	}
	bl := strings.ToLower(body)
	for _, p := range patterns {
		if strings.Contains(bl, strings.ToLower(p)) {
			return true
		}
	}
	return false
}

func chooseBaseURL(target string, ports []PortInfo) string {
	// Şema seçimi
	scheme := schemeMode
	if scheme == "auto" {
		has443 := false
		has80 := false
		for _, p := range ports {
			if p.Port == 443 || p.Port == 8443 {
				has443 = true
			}
			if p.Port == 80 || p.Port == 8080 || p.Port == 8000 {
				has80 = true
			}
		}
		if has443 {
			scheme = "https"
		} else if has80 {
			scheme = "http"
		} else {
			scheme = "http"
		}
	}
	return scheme + "://" + target + "/"
}

func whoisServerForHost(target string) string {
	// TLD'ye göre basit seçim
	if strings.HasSuffix(strings.ToLower(target), ".com") || strings.HasSuffix(strings.ToLower(target), ".net") {
		return "whois.verisign-grs.com"
	}
	if strings.HasSuffix(strings.ToLower(target), ".org") {
		return "whois.pir.org"
	}
	// default: verisign deneyelim
	return "whois.verisign-grs.com"
}

// Retry helper
func withRetry(fn func() error) error {
	var err error
	for attempt := 0; attempt <= retries; attempt++ {
		err = fn()
		if err == nil {
			return nil
		}
		time.Sleep(retryBackoff * time.Duration(attempt+1))
	}
	return err
}

func containsPrefix(arr []string, prefix string) bool {
	for _, s := range arr {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func dedupStrings(in []string) []string {
	m := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(strings.ToLower(s))
		if s == "" {
			continue
		}
		if _, ok := m[s]; ok {
			continue
		}
		m[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// String'i belirtilen uzunlukta keser
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func hackerTargetSubdomains(domain string) ([]string, error) {
	// https://api.hackertarget.com/hostsearch/?q=domain -> csv: sub,ip per line
	u := "https://api.hackertarget.com/hostsearch/?q=" + url.QueryEscape(domain)

	var lastErr error

	// OSINT-specific retry logic
	for attempt := 0; attempt <= osintRetries; attempt++ {
		// Apply OSINT rate limiting
		if osintPermitCh != nil {
			<-osintPermitCh
		}

		// Daha uzun timeout ile deneme
		ctx, cancel := context.WithTimeout(context.Background(), osintTimeout)
		defer cancel()

		req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
		if err != nil {
			lastErr = err
			if attempt < osintRetries {
				time.Sleep(osintBackoff * time.Duration(attempt+1))
				continue
			}
			return nil, err
		}
		req.Header.Set("User-Agent", "GoHunt/1.0")

		client := &http.Client{Timeout: osintTimeout}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			if attempt < osintRetries {
				time.Sleep(osintBackoff * time.Duration(attempt+1))
				continue
			}
			return nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			if attempt < osintRetries {
				time.Sleep(osintBackoff * time.Duration(attempt+1))
				continue
			}
			return nil, lastErr
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
		if err != nil {
			lastErr = err
			if attempt < osintRetries {
				time.Sleep(osintBackoff * time.Duration(attempt+1))
				continue
			}
			return nil, err
		}

		// HackerTarget bazen hata mesajı döndürür, kontrol et
		bodyStr := string(body)
		if strings.Contains(bodyStr, "error") || strings.Contains(bodyStr, "limit") || strings.Contains(bodyStr, "quota") {
			lastErr = fmt.Errorf("API limiti veya hata: %s", strings.TrimSpace(bodyStr))
			if attempt < osintRetries {
				time.Sleep(osintBackoff * time.Duration(attempt+1))
				continue
			}
			return nil, lastErr
		}

		r := csv.NewReader(strings.NewReader(bodyStr))
		r.FieldsPerRecord = -1
		lines, err := r.ReadAll()
		if err != nil {
			lastErr = err
			if attempt < osintRetries {
				time.Sleep(osintBackoff * time.Duration(attempt+1))
				continue
			}
			return nil, err
		}

		out := []string{}
		for _, rec := range lines {
			if len(rec) == 0 {
				continue
			}
			s := strings.ToLower(strings.TrimSpace(rec[0]))
			if strings.HasSuffix(s, "."+domain) {
				// Clean subdomain name (remove any IP if present)
				cleanSub := s
				if strings.Contains(s, ",") {
					parts := strings.Split(s, ",")
					if len(parts) > 0 {
						cleanSub = strings.TrimSpace(parts[0])
					}
				}
				out = append(out, cleanSub)
			}
		}
		return dedupStrings(out), nil
	}

	return nil, lastErr
}

// Çıktı formatları: CSV, XML
func writeCSV(res ScanResult, filename string) error {
	// önce memory buffer'a yaz, başarısız olursa dosyayı etkileme
	buf := &bytes.Buffer{}
	w := csv.NewWriter(buf)
	if err := w.Write([]string{"Section", "Value1", "Value2", "Value3"}); err != nil {
		return err
	}
	// büyük veri için periyodik Flush
	flushEvery := 1000
	row := 0
	for _, s := range res.Subdomains {
		if err := w.Write([]string{"subdomain", s.Name, s.Status, ""}); err != nil {
			return err
		}
		row++
		if row%flushEvery == 0 {
			w.Flush()
			if w.Error() != nil {
				return w.Error()
			}
		}
	}
	for _, p := range res.OpenPorts {
		if err := w.Write([]string{"port", strconv.Itoa(p.Port), p.Service, p.Banner}); err != nil {
			return err
		}
		row++
		if row%flushEvery == 0 {
			w.Flush()
			if w.Error() != nil {
				return w.Error()
			}
		}
	}
	for _, c := range res.CVEs {
		if err := w.Write([]string{"cve", c.ID, c.Severity, c.Description}); err != nil {
			return err
		}
		row++
		if row%flushEvery == 0 {
			w.Flush()
			if w.Error() != nil {
				return w.Error()
			}
		}
	}
	for _, t := range res.WebTechs {
		if err := w.Write([]string{"tech", t, "", ""}); err != nil {
			return err
		}
		row++
		if row%flushEvery == 0 {
			w.Flush()
			if w.Error() != nil {
				return w.Error()
			}
		}
	}
	if res.ResolvedIP != "" {
		if err := w.Write([]string{"ip", res.ResolvedIP, "", ""}); err != nil {
			return err
		}
	}
	if res.Whois != "" {
		if err := w.Write([]string{"whois", strings.ReplaceAll(res.Whois, "\n", " "), "", ""}); err != nil {
			return err
		}
	}
	for _, v := range res.VulnResults {
		if err := w.Write([]string{"vuln", v, "", ""}); err != nil {
			return err
		}
	}
	w.Flush()
	if w.Error() != nil {
		return w.Error()
	}
	// dosyaya atomik yazma
	tmp := filename + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0644); err != nil {
		return err
	}
	return os.Rename(tmp, filename)
}

type xmlResult struct {
	XMLName    xml.Name  `xml:"gohunt"`
	Target     string    `xml:"target"`
	IP         string    `xml:"ip"`
	Subdomains []string  `xml:"subdomains>subdomain"`
	Ports      []xmlPort `xml:"ports>port"`
	CVEs       []xmlCVE  `xml:"cves>cve"`
	Techs      []string  `xml:"techs>tech"`
	Whois      string    `xml:"whois"`
	Vulns      []string  `xml:"vulns>vuln"`
}
type xmlPort struct {
	Number  int    `xml:"number,attr"`
	Service string `xml:"service,attr"`
	Banner  string `xml:"banner"`
}
type xmlCVE struct {
	ID          string  `xml:"id,attr"`
	Severity    string  `xml:"severity,attr"`
	CVSS        float64 `xml:"cvss,attr"`
	Description string  `xml:"description"`
}

func writeXML(res ScanResult, filename string) error {
	// Subdomain isimlerini string array'e dönüştür
	var subdomainNames []string
	for _, s := range res.Subdomains {
		subdomainNames = append(subdomainNames, s.Name+" ("+s.Status+")")
	}

	xr := xmlResult{Target: res.Target, IP: res.ResolvedIP, Subdomains: subdomainNames, Techs: res.WebTechs, Whois: res.Whois, Vulns: res.VulnResults}
	for _, p := range res.OpenPorts {
		xr.Ports = append(xr.Ports, xmlPort{Number: p.Port, Service: p.Service, Banner: p.Banner})
	}
	for _, c := range res.CVEs {
		xr.CVEs = append(xr.CVEs, xmlCVE{ID: c.ID, Severity: c.Severity, CVSS: c.CVSS, Description: c.Description})
	}
	out, err := xml.MarshalIndent(xr, "", "  ")
	if err != nil {
		return err
	}
	out = append([]byte(xml.Header), out...)
	return os.WriteFile(filename, out, 0644)
}

// TXT output (pretty plain text)
func writeTXT(res ScanResult, filename string) error {
	b := &strings.Builder{}
	fmt.Fprintf(b, "GoHunt Report - %s\n", res.Target)
	fmt.Fprintln(b, strings.Repeat("=", 72))
	if res.ResolvedIP != "" {
		fmt.Fprintf(b, "IP: %s\n", res.ResolvedIP)
	}
	if len(res.Subdomains) > 0 {
		fmt.Fprintln(b, "\nSubdomains:")
		for _, s := range res.Subdomains {
			fmt.Fprintf(b, "  - %s [%s]\n", s.Name, s.Status)
		}
	}
	if len(res.OpenPorts) > 0 {
		fmt.Fprintln(b, "\nOpen Ports:")
		for _, p := range res.OpenPorts {
			line := fmt.Sprintf("  - %d/tcp %s", p.Port, p.Service)
			if strings.TrimSpace(p.Banner) != "" {
				line += " - " + strings.TrimSpace(p.Banner)
			}
			fmt.Fprintln(b, line)
		}
	}
	if len(res.CVEs) > 0 {
		fmt.Fprintln(b, "\nCVEs:")
		for _, c := range res.CVEs {
			fmt.Fprintf(b, "  - %s [%s] CVSS %.1f - %s\n", c.ID, c.Severity, c.CVSS, c.Description)
			if c.Source != "" {
				fmt.Fprintf(b, "      Source: %s\n", c.Source)
			}
			if c.ExploitLink != "" {
				fmt.Fprintf(b, "      Ref: %s\n", c.ExploitLink)
			}
		}
	}
	if len(res.WebTechs) > 0 {
		fmt.Fprintln(b, "\nWeb Technologies:")
		for _, t := range res.WebTechs {
			fmt.Fprintf(b, "  - %s\n", t)
		}
	}
	if res.Whois != "" {
		fmt.Fprintln(b, "\nWHOIS:")
		fmt.Fprintln(b, indentMultiline(res.Whois, "  "))
	}
	if len(res.VulnResults) > 0 {
		fmt.Fprintln(b, "\nVulnerability Tests:")
		for _, v := range res.VulnResults {
			fmt.Fprintf(b, "  - %s\n", v)
		}
	}
	if len(res.Warnings) > 0 {
		fmt.Fprintln(b, "\nWarnings:")
		for _, w := range res.Warnings {
			fmt.Fprintf(b, "  - %s\n", w)
		}
	}
	if len(res.Errors) > 0 {
		fmt.Fprintln(b, "\nErrors:")
		for _, e := range res.Errors {
			fmt.Fprintf(b, "  - %s\n", e)
		}
	}
	fmt.Fprintf(b, "\nStarted: %s\n", res.ScanStart)
	fmt.Fprintf(b, "Duration: %s\n", res.ScanDuration)
	return os.WriteFile(filename, []byte(b.String()), 0644)
}

func indentMultiline(s, prefix string) string {
	lines := strings.Split(s, "\n")
	for i := range lines {
		lines[i] = prefix + lines[i]
	}
	return strings.Join(lines, "\n")
}
