package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/nocktechnologies/nockguard/internal/gateway"
	"github.com/nocktechnologies/nockguard/internal/policy"
	"github.com/nocktechnologies/nockguard/internal/proxy"
)

func runMCPGateway(args []string) int {
	f := flag.NewFlagSet("mcp-gateway", flag.ContinueOnError)
	path := f.String("config", "", "gateway YAML configuration file")
	if err := f.Parse(args); err != nil {
		return 1
	}
	if *path == "" || f.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: nockguard mcp-gateway --config <path>")
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := serveMCPGateway(ctx, *path); err != nil {
		fmt.Fprintf(os.Stderr, "mcp-gateway: %v\n", err)
		return 1
	}
	return 0
}

func serveMCPGateway(ctx context.Context, path string) error {
	c, err := gateway.Load(path)
	if err != nil {
		return err
	}
	upstreamToken, err := gateway.Secret(c.UpstreamTokenEnv)
	if err != nil {
		return err
	}
	introspectionToken, err := gateway.Secret(c.IntrospectionTokenEnv)
	if err != nil {
		return err
	}
	if upstreamToken == introspectionToken {
		return fmt.Errorf("upstream and introspection credentials must be different")
	}
	engine, err := policy.Load(c.Policy)
	if err != nil {
		return err
	}
	if !engine.HasPolicyFor(c.Agent) {
		return fmt.Errorf("configured agent has no policy")
	}
	if os.Getenv(policy.AgentKeyEnvName(c.Agent)) == "" {
		return fmt.Errorf("gateway requires the per-agent Ed25519 signing key in %s", policy.AgentKeyEnvName(c.Agent))
	}
	validator, err := engine.ValidatorFor(c.Agent)
	if err != nil {
		return err
	}
	limiter, err := engine.LimiterFor(c.Agent)
	if err != nil {
		return err
	}
	trustAccumulator, err := engine.TrustFor(c.Agent)
	if err != nil {
		return err
	}
	auditor, err := engine.AuditorFor(c.Agent)
	if err != nil {
		return err
	}
	defer auditor.Close()
	if !auditor.Enabled() {
		return fmt.Errorf("gateway requires audit.enabled: true")
	}
	forwarder, err := engine.Forwarder()
	if err != nil {
		return err
	}
	forwarder.Start()
	defer forwarder.Stop()
	logger := log.New(os.Stderr, "[nockguard-mcp-gateway] ", log.LstdFlags)
	for _, warning := range engine.Warnings() {
		logger.Printf("policy warning: %s", warning)
	}
	approver := buildApprover(logger)
	// One agent's quota, trust and audit objects are shared. The mutable card
	// state and audit sequencing belong to each fresh session gate.
	g, err := gateway.New(c, func() http.Handler {
		gate := proxy.NewStdioProxy(nil, c.Agent, engine, validator, limiter, auditor, forwarder, logger).
			WithTrust(trustAccumulator).WithApprover(approver)
		return proxy.NewHTTPListener("", c.Upstream, gate, logger).WithUpstreamAgentToken(upstreamToken)
	})
	if err != nil {
		return err
	}
	logger.Printf("starting gateway listen=%s resource=%s agent=%s", c.Listen, c.Resource, c.Agent)
	return g.Run(ctx)
}
