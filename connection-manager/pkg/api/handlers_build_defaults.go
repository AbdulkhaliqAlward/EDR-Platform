package api

import (
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/labstack/echo/v4"
)

// DefaultAgentServerDomain is used when the deployment has no DNS name for the
// gRPC endpoint. The installer writes it to the endpoint's hosts file next to
// the server IP, so it does not need to exist in DNS.
const DefaultAgentServerDomain = "edr.local"

// AgentBuildDefaults are the connection settings an agent build should embed
// and the install command should carry: the address agents actually reach.
type AgentBuildDefaults struct {
	ServerIP     string `json:"server_ip"`
	ServerDomain string `json:"server_domain"`
	ServerPort   string `json:"server_port"`
	// Where each value came from (env, c2_grpc_address, request_host, dns, default).
	Sources map[string]string `json:"sources"`
}

// GetAgentBuildDefaults returns the server address to prefill agent builds.
// GET /api/v1/agent/build-defaults
func (h *Handlers) GetAgentBuildDefaults(c echo.Context) error {
	host := c.Request().Header.Get("X-Forwarded-Host")
	if host == "" {
		host = c.Request().Host
	}
	if i := strings.IndexByte(host, ','); i >= 0 {
		host = host[:i]
	}
	return c.JSON(http.StatusOK, ResolveAgentBuildDefaults(h.grpcAddress, host, os.Getenv, net.LookupIP))
}

// ResolveAgentBuildDefaults derives the defaults (pure apart from the injected
// env/DNS lookups, for tests). Order:
//   - port:   AGENT_SERVER_PORT, else the port of C2_GRPC_ADDRESS (the public
//     gRPC port agents use, e.g. 47051 behind Docker), else 47051.
//   - domain: AGENT_SERVER_DOMAIN, else the C2_GRPC_ADDRESS host when it is a
//     name, else the dashboard host when it is a name, else edr.local.
//   - ip:     AGENT_SERVER_IP, else the dashboard host when it is an IP (the
//     address the administrator reaches the server on), else that host
//     resolved through DNS, else the domain resolved through DNS.
func ResolveAgentBuildDefaults(grpcAddress, requestHost string, env func(string) string, lookup func(string) ([]net.IP, error)) AgentBuildDefaults {
	d := AgentBuildDefaults{Sources: map[string]string{}}
	grpcHost, grpcPort := splitHostPortLoose(grpcAddress)
	reqHost, _ := splitHostPortLoose(requestHost)

	switch {
	case validPort(env("AGENT_SERVER_PORT")):
		d.ServerPort, d.Sources["server_port"] = strings.TrimSpace(env("AGENT_SERVER_PORT")), "env"
	case validPort(grpcPort) && !isLoopbackAddr(grpcHost):
		d.ServerPort, d.Sources["server_port"] = grpcPort, "c2_grpc_address"
	default:
		d.ServerPort, d.Sources["server_port"] = "47051", "default"
	}

	switch {
	case isDNSName(env("AGENT_SERVER_DOMAIN")):
		d.ServerDomain, d.Sources["server_domain"] = strings.TrimSpace(env("AGENT_SERVER_DOMAIN")), "env"
	case isDNSName(grpcHost) && !isLoopbackAddr(grpcHost):
		d.ServerDomain, d.Sources["server_domain"] = grpcHost, "c2_grpc_address"
	case isDNSName(reqHost) && !isLoopbackAddr(reqHost):
		d.ServerDomain, d.Sources["server_domain"] = reqHost, "request_host"
	default:
		d.ServerDomain, d.Sources["server_domain"] = DefaultAgentServerDomain, "default"
	}

	if ip := net.ParseIP(strings.TrimSpace(env("AGENT_SERVER_IP"))); usableIP(ip) {
		d.ServerIP, d.Sources["server_ip"] = ip.String(), "env"
	} else if ip := net.ParseIP(reqHost); usableIP(ip) {
		d.ServerIP, d.Sources["server_ip"] = ip.String(), "request_host"
	} else if ip := firstIPv4(lookup, reqHost); ip != "" {
		d.ServerIP, d.Sources["server_ip"] = ip, "dns"
	} else if ip := firstIPv4(lookup, d.ServerDomain); ip != "" {
		d.ServerIP, d.Sources["server_ip"] = ip, "dns"
	}
	return d
}

func splitHostPortLoose(addr string) (string, string) {
	addr = strings.TrimSpace(addr)
	if h, p, err := net.SplitHostPort(addr); err == nil {
		return strings.Trim(h, "[]"), p
	}
	return strings.Trim(addr, "[]"), ""
}

func validPort(p string) bool {
	p = strings.TrimSpace(p)
	if p == "" || len(p) > 5 {
		return false
	}
	n := 0
	for _, r := range p {
		if r < '0' || r > '9' {
			return false
		}
		n = n*10 + int(r-'0')
	}
	return n > 0 && n < 65536
}

func isLoopbackAddr(h string) bool {
	h = strings.ToLower(strings.TrimSpace(h))
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// isDNSName reports a usable host name (not an IP, not empty).
func isDNSName(h string) bool {
	h = strings.TrimSpace(h)
	if h == "" || len(h) > 253 || net.ParseIP(h) != nil {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for _, r := range label {
			if !(r == '-' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') {
				return false
			}
		}
	}
	return true
}

func usableIP(ip net.IP) bool {
	return ip != nil && !ip.IsLoopback() && !ip.IsUnspecified() && !ip.IsMulticast() && !ip.IsLinkLocalUnicast()
}

func firstIPv4(lookup func(string) ([]net.IP, error), host string) string {
	if lookup == nil || !isDNSName(host) || isLoopbackAddr(host) {
		return ""
	}
	ips, err := lookup(host)
	if err != nil {
		return ""
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil && usableIP(v4) {
			return v4.String()
		}
	}
	return ""
}

// validateBuildServerConfig checks the server settings a build embeds (and the
// install command shows). A missing port defaults to the public gRPC port, not
// the container-internal 50051. Returns "" when valid.
func validateBuildServerConfig(req *BuildAgentRequest, grpcAddress string) string {
	req.ServerIP = strings.TrimSpace(req.ServerIP)
	req.ServerDomain = strings.TrimSpace(req.ServerDomain)
	req.ServerPort = strings.TrimSpace(req.ServerPort)
	if req.ServerPort == "" {
		req.ServerPort = ResolveAgentBuildDefaults(grpcAddress, "", func(string) string { return "" }, nil).ServerPort
	}
	if !validPort(req.ServerPort) {
		return "server_port must be a number between 1 and 65535"
	}
	if req.SkipConfig {
		return ""
	}
	if req.ServerIP == "" || req.ServerDomain == "" {
		return "server_ip and server_domain are required when not skipping config"
	}
	if ip := net.ParseIP(req.ServerIP); !usableIP(ip) {
		return "server_ip must be a reachable IPv4/IPv6 address (not loopback)"
	}
	if !isDNSName(req.ServerDomain) {
		return "server_domain must be a host name (letters, digits, dots and hyphens)"
	}
	return ""
}
