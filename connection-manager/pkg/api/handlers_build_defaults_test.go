package api

import (
	"errors"
	"net"
	"testing"
)

func TestResolveAgentBuildDefaults(t *testing.T) {
	noEnv := func(string) string { return "" }
	noDNS := func(string) ([]net.IP, error) { return nil, errors.New("no dns") }
	cases := []struct {
		name             string
		grpc, host       string
		env              map[string]string
		dns              map[string][]net.IP
		ip, domain, port string
	}{
		// The production compose: C2_GRPC_ADDRESS=edr.local:47051, dashboard opened at the public IP.
		{"compose on public IP", "edr.local:47051", "13.61.147.131", nil, nil, "13.61.147.131", "edr.local", "47051"},
		{"dashboard behind a port", "edr.local:47051", "13.61.147.131:30088", nil, nil, "13.61.147.131", "edr.local", "47051"},
		// Dashboard opened by DNS name: the name is resolved to the IP.
		{"dashboard by name", "localhost:50051", "edr.example.com", nil, map[string][]net.IP{"edr.example.com": {net.ParseIP("203.0.113.7")}}, "203.0.113.7", "edr.example.com", "47051"},
		// Nothing configured, opened on localhost: no IP guess, sensible defaults.
		{"local dev", "localhost:50051", "localhost:5173", nil, nil, "", "edr.local", "47051"},
		// Explicit ops settings win.
		{"env overrides", "edr.local:47051", "13.61.147.131", map[string]string{"AGENT_SERVER_IP": "198.51.100.2", "AGENT_SERVER_DOMAIN": "c2.corp.example", "AGENT_SERVER_PORT": "443"}, nil, "198.51.100.2", "c2.corp.example", "443"},
		// Invalid env values are ignored, never echoed into the install command.
		{"invalid env ignored", "edr.local:47051", "13.61.147.131", map[string]string{"AGENT_SERVER_IP": "not-an-ip", "AGENT_SERVER_DOMAIN": "bad domain; rm", "AGENT_SERVER_PORT": "99999"}, nil, "13.61.147.131", "edr.local", "47051"},
		// Loopback addresses are never offered to remote agents.
		{"loopback host", "edr.local:47051", "127.0.0.1:30088", nil, nil, "", "edr.local", "47051"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := noEnv
			if tc.env != nil {
				env = func(k string) string { return tc.env[k] }
			}
			lookup := noDNS
			if tc.dns != nil {
				lookup = func(h string) ([]net.IP, error) {
					if ips, ok := tc.dns[h]; ok {
						return ips, nil
					}
					return nil, errors.New("nxdomain")
				}
			}
			d := ResolveAgentBuildDefaults(tc.grpc, tc.host, env, lookup)
			if d.ServerIP != tc.ip || d.ServerDomain != tc.domain || d.ServerPort != tc.port {
				t.Fatalf("got ip=%q domain=%q port=%q (%v)", d.ServerIP, d.ServerDomain, d.ServerPort, d.Sources)
			}
		})
	}
}

func TestValidateBuildServerConfig(t *testing.T) {
	ok := BuildAgentRequest{ServerIP: " 13.61.147.131 ", ServerDomain: "edr.local"}
	if msg := validateBuildServerConfig(&ok, "edr.local:47051"); msg != "" || ok.ServerPort != "47051" || ok.ServerIP != "13.61.147.131" {
		t.Fatalf("valid request rejected or port not defaulted to the public gRPC port: %q %+v", msg, ok)
	}
	skip := BuildAgentRequest{SkipConfig: true}
	if msg := validateBuildServerConfig(&skip, "edr.local:47051"); msg != "" || skip.ServerPort != "47051" {
		t.Fatalf("skip-config build: %q %+v", msg, skip)
	}
	for _, bad := range []BuildAgentRequest{
		{ServerIP: "", ServerDomain: "edr.local"},
		{ServerIP: "13.61.147.131", ServerDomain: ""},
		{ServerIP: "127.0.0.1", ServerDomain: "edr.local"},
		{ServerIP: "not-an-ip", ServerDomain: "edr.local"},
		{ServerIP: "13.61.147.131", ServerDomain: "edr.local -X main.Evil=1"},
		{ServerIP: "13.61.147.131", ServerDomain: "edr.local", ServerPort: "70000"},
	} {
		b := bad
		if msg := validateBuildServerConfig(&b, "edr.local:47051"); msg == "" {
			t.Fatalf("accepted invalid config %+v", bad)
		}
	}
}
