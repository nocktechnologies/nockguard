// Package gateway provides a single-agent OAuth resource boundary for HTTP MCP.
package gateway

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config contains references to secrets, never secret values.
type Config struct {
	Listen                  string   `yaml:"listen"`
	Resource                string   `yaml:"resource"`
	Issuer                  string   `yaml:"issuer"`
	IntrospectionURL        string   `yaml:"introspection_url"`
	IntrospectionAuthHeader string   `yaml:"introspection_auth_header"`
	IntrospectionTokenEnv   string   `yaml:"introspection_token_env"`
	Subject                 string   `yaml:"subject"`
	ClientID                string   `yaml:"client_id"`
	Scope                   string   `yaml:"scope"`
	Agent                   string   `yaml:"agent"`
	Policy                  string   `yaml:"policy"`
	Upstream                string   `yaml:"upstream"`
	UpstreamTokenEnv        string   `yaml:"upstream_token_env"`
	AllowedOrigins          []string `yaml:"allowed_origins"`
}

func Load(path string) (Config, error) {
	var c Config
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	d := yaml.NewDecoder(bytes.NewReader(b))
	d.KnownFields(true)
	if err := d.Decode(&c); err != nil {
		return c, err
	}
	var extra interface{}
	if err := d.Decode(&extra); err != io.EOF {
		return c, fmt.Errorf("gateway config must contain one YAML document")
	}
	return c, c.Validate()
}

// Validate deliberately permits no insecure HTTP escape hatch, even for auth.
func (c Config) Validate() error {
	host, port, err := net.SplitHostPort(c.Listen)
	if err != nil || port == "" || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return fmt.Errorf("gateway listen must be explicit loopback host:port")
	}
	for name, raw := range map[string]string{"resource": c.Resource, "issuer": c.Issuer, "introspection_url": c.IntrospectionURL, "upstream": c.Upstream} {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.ContainsAny(raw, "\r\n\t ") {
			return fmt.Errorf("%s must be an HTTPS URL without credentials, query or fragment", name)
		}
		if name == "resource" && (u.Path != "/mcp" || u.RawPath != "") {
			return fmt.Errorf("resource must have the path /mcp")
		}
	}
	for name, v := range map[string]string{"subject": c.Subject, "client_id": c.ClientID, "scope": c.Scope, "agent": c.Agent, "policy": c.Policy, "introspection_token_env": c.IntrospectionTokenEnv, "upstream_token_env": c.UpstreamTokenEnv} {
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	if len(strings.Fields(c.Scope)) != 1 || strings.TrimSpace(c.Scope) != c.Scope {
		return fmt.Errorf("scope must be one scope name")
	}
	if c.IntrospectionAuthHeader != "Authorization" && c.IntrospectionAuthHeader != "X-Agent-Token" {
		return fmt.Errorf("introspection_auth_header must be Authorization or X-Agent-Token")
	}
	if c.IntrospectionTokenEnv == c.UpstreamTokenEnv {
		return fmt.Errorf("introspection and upstream credentials must be separate")
	}
	for _, origin := range c.AllowedOrigins {
		u, err := url.Parse(origin)
		if err != nil || u.Scheme != "https" || u.Host == "" || origin != "https://"+u.Host {
			return fmt.Errorf("allowed_origins must contain HTTPS origins without paths")
		}
	}
	return nil
}

// Secret rejects whitespace/control characters that cannot safely form a token.
func Secret(name string) (string, error) {
	s := os.Getenv(name)
	if s == "" {
		return "", fmt.Errorf("credential environment variable %s is empty", name)
	}
	for _, r := range s {
		if r < 33 || r > 126 {
			return "", fmt.Errorf("credential environment variable %s is not a printable token", name)
		}
	}
	return s, nil
}
