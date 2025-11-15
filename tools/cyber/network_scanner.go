package cyber

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/voocel/mas/runtime"
	"github.com/voocel/mas/schema"
	"github.com/voocel/mas/tools"
)

var (
	defaultScanPorts = []int{
		21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 161, 389, 443, 445, 465, 587,
		993, 995, 1025, 1433, 1521, 2049, 2375, 3306, 3389, 5432, 5900, 5986, 6379,
		7001, 8000, 8080, 8443, 9200, 11211,
	}

	portServiceHints = map[int]string{
		21:    "FTP",
		22:    "SSH",
		23:    "Telnet",
		25:    "SMTP",
		53:    "DNS",
		80:    "HTTP",
		110:   "POP3",
		135:   "MS RPC",
		139:   "SMB",
		143:   "IMAP",
		161:   "SNMP",
		389:   "LDAP",
		443:   "HTTPS",
		445:   "SMB",
		465:   "SMTPS",
		587:   "Submission",
		993:   "IMAPS",
		995:   "POP3S",
		1433:  "MSSQL",
		1521:  "Oracle",
		2049:  "NFS",
		2375:  "Docker API",
		3306:  "MySQL",
		3389:  "RDP",
		5432:  "PostgreSQL",
		5900:  "VNC",
		5986:  "WinRM",
		6379:  "Redis",
		7001:  "WebLogic",
		8000:  "HTTP-alt",
		8080:  "HTTP-alt",
		8443:  "HTTPS-alt",
		9200:  "Elasticsearch",
		11211: "Memcached",
	}

	portVulnerabilityHints = map[int][]string{
		21:    {"Weak or anonymous FTP access", "Plain-text credential exposure"},
		22:    {"Password-based SSH logins susceptible to brute force", "Outdated SSH daemons"},
		23:    {"Telnet transmits credentials in cleartext"},
		25:    {"Open relays abused for spam", "STARTTLS downgrade attacks"},
		53:    {"Open resolvers used for amplification"},
		80:    {"Missing HTTPS redirects", "Outdated web stacks"},
		110:   {"Plain-text mail credentials"},
		135:   {"MS RPC exposure enabling lateral movement"},
		139:   {"SMBv1 vulnerable to EternalBlue"},
		143:   {"IMAP plaintext authentication"},
		389:   {"Anonymous LDAP binds, weak auth"},
		443:   {"Weak TLS ciphers or certificates"},
		445:   {"SMB remote code execution (EternalBlue/EternalRomance)"},
		3306:  {"Default MySQL credentials", "Unauthenticated remote access"},
		3389:  {"RDP brute-force, BlueKeep (CVE-2019-0708)"},
		5432:  {"Default Postgres credentials"},
		5900:  {"Unauthenticated VNC access"},
		6379:  {"Unauthenticated Redis instances"},
		9200:  {"Anonymous Elasticsearch clusters"},
		11211: {"Open memcached amplification"},
	}
)

// NetworkScannerTool performs lightweight network recon on domains/hosts.
type NetworkScannerTool struct {
	*tools.BaseTool
	defaultPorts []int
	portTimeout  time.Duration
}

// NetworkScanInput configures the scan.
type NetworkScanInput struct {
	Domain         string   `json:"domain" description:"Domain or host to scan"`
	Ports          []int    `json:"ports,omitempty" description:"Custom ports to scan"`
	MaxConcurrency int      `json:"max_concurrency,omitempty" description:"Number of concurrent probes"`
	TimeoutSeconds int      `json:"timeout_seconds,omitempty" description:"Dial timeout per port"`
	Notes          []string `json:"notes,omitempty" description:"Free-form analyst notes"`
}

// PortFinding captures a single port result.
type PortFinding struct {
	Port             int      `json:"port"`
	Service          string   `json:"service"`
	Status           string   `json:"status"`
	VulnerabilityRef []string `json:"vulnerabilities,omitempty"`
	DurationMS       int64    `json:"duration_ms"`
	Error            string   `json:"error,omitempty"`
}

// NetworkScanReport summarizes the scan output.
type NetworkScanReport struct {
	Success      bool          `json:"success"`
	Domain       string        `json:"domain"`
	ResolvedIPs  []string      `json:"resolved_ips"`
	Findings     []PortFinding `json:"findings"`
	Notes        []string      `json:"notes,omitempty"`
	StartedAt    time.Time     `json:"started_at"`
	DurationMS   int64         `json:"duration_ms"`
	OpenServices int           `json:"open_services"`
}

// NewNetworkScannerTool constructs a scanning tool.
func NewNetworkScannerTool(defaultPorts []int) *NetworkScannerTool {
	if len(defaultPorts) == 0 {
		defaultPorts = defaultScanPorts
	}

	schema := tools.CreateToolSchema(
		"Perform targeted TCP scans against a domain or host to discover exposed services and common weaknesses.",
		map[string]interface{}{
			"domain":          tools.StringProperty("Domain, hostname, or IPv4 address to scan"),
			"ports":           tools.ArrayProperty("Optional override for scanned ports", "number"),
			"max_concurrency": tools.NumberProperty("Simultaneous probes (default 50)"),
			"timeout_seconds": tools.NumberProperty("Dial timeout per port (default 3s)"),
			"notes":           tools.ArrayProperty("Analyst provided notes", "string"),
		},
		[]string{"domain"},
	)

	return &NetworkScannerTool{
		BaseTool:     tools.NewBaseTool("network_scanner", "Network recon and exposure mapper", schema),
		defaultPorts: defaultPorts,
		portTimeout:  3 * time.Second,
	}
}

// Execute performs the scan.
func (t *NetworkScannerTool) Execute(ctx runtime.Context, input json.RawMessage) (json.RawMessage, error) {
	var params NetworkScanInput
	if err := json.Unmarshal(input, &params); err != nil {
		return nil, schema.NewToolError(t.Name(), "parse_input", err)
	}

	domain := strings.TrimSpace(params.Domain)
	if domain == "" {
		return nil, schema.NewValidationError("domain", params.Domain, "domain or host is required")
	}

	ports := t.defaultPorts
	if len(params.Ports) > 0 {
		ports = sanitizePorts(params.Ports)
	}
	if len(ports) == 0 {
		return nil, schema.NewValidationError("ports", params.Ports, "no valid ports provided")
	}

	timeout := t.portTimeout
	if params.TimeoutSeconds > 0 {
		timeout = time.Duration(params.TimeoutSeconds) * time.Second
	}

	maxConcurrency := params.MaxConcurrency
	if maxConcurrency <= 0 {
		maxConcurrency = 50
	}

	start := time.Now()
	ips, err := net.LookupIP(domain)
	if err != nil {
		return nil, schema.NewToolError(t.Name(), "resolve_domain", err)
	}
	if len(ips) == 0 {
		return nil, schema.NewToolError(t.Name(), "resolve_domain", fmt.Errorf("no IPs resolved for %s", domain))
	}

	ipStrings := make([]string, 0, len(ips))
	for _, ip := range ips {
		ipStrings = append(ipStrings, ip.String())
	}

	results := t.scanPorts(ctx, ips, ports, timeout, maxConcurrency)
	openCount := 0
	for _, f := range results {
		if f.Status == "open" {
			openCount++
		}
	}

	report := NetworkScanReport{
		Success:      true,
		Domain:       domain,
		ResolvedIPs:  ipStrings,
		Findings:     results,
		Notes:        params.Notes,
		StartedAt:    start,
		DurationMS:   time.Since(start).Milliseconds(),
		OpenServices: openCount,
	}

	payload, err := json.Marshal(report)
	if err != nil {
		return nil, schema.NewToolError(t.Name(), "marshal_output", err)
	}
	return payload, nil
}

func (t *NetworkScannerTool) scanPorts(ctx context.Context, ips []net.IP, ports []int, timeout time.Duration, maxConcurrency int) []PortFinding {
	type job struct {
		ip   net.IP
		port int
	}

	jobs := make(chan job)
	results := make(chan PortFinding)
	var wg sync.WaitGroup

	worker := func() {
		defer wg.Done()
		for j := range jobs {
			res := t.scanPort(ctx, j.ip, j.port, timeout)
			results <- res
		}
	}

	for i := 0; i < maxConcurrency; i++ {
		wg.Add(1)
		go worker()
	}

	go func() {
		for _, ip := range ips {
			for _, port := range ports {
				select {
				case <-ctx.Done():
					close(jobs)
					return
				case jobs <- job{ip: ip, port: port}:
				}
			}
		}
		close(jobs)
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	findings := make([]PortFinding, 0, len(ports)*len(ips))
	for res := range results {
		findings = append(findings, res)
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Port == findings[j].Port {
			return findings[i].Service < findings[j].Service
		}
		return findings[i].Port < findings[j].Port
	})

	return findings
}

func (t *NetworkScannerTool) scanPort(ctx context.Context, ip net.IP, port int, timeout time.Duration) PortFinding {
	address := net.JoinHostPort(ip.String(), strconv.Itoa(port))
	start := time.Now()

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	elapsed := time.Since(start).Milliseconds()

	finding := PortFinding{
		Port:       port,
		Service:    portServiceHints[port],
		DurationMS: elapsed,
	}

	if err != nil {
		finding.Status = "closed"
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			finding.Error = "timeout"
		}
		return finding
	}
	defer conn.Close()

	finding.Status = "open"
	if hints, ok := portVulnerabilityHints[port]; ok {
		finding.VulnerabilityRef = hints
	}

	return finding
}

func sanitizePorts(ports []int) []int {
	seen := make(map[int]struct{})
	clean := make([]int, 0, len(ports))
	for _, port := range ports {
		if port <= 0 || port > 65535 {
			continue
		}
		if _, exists := seen[port]; exists {
			continue
		}
		seen[port] = struct{}{}
		clean = append(clean, port)
	}
	sort.Ints(clean)
	return clean
}
