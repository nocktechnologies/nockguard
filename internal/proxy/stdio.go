package proxy

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"sync"

	"github.com/nocktechnologies/nockguard/internal/jsonrpc"
	"github.com/nocktechnologies/nockguard/internal/policy"
	"github.com/nocktechnologies/nockguard/internal/validate"
)

type StdioProxy struct {
	upstream  []string
	agent     string
	engine    *policy.Engine
	validator *validate.Validator
	logger    *log.Logger
}

func NewStdioProxy(upstream []string, agent string, engine *policy.Engine, validator *validate.Validator, logger *log.Logger) *StdioProxy {
	return &StdioProxy{
		upstream:  upstream,
		agent:     agent,
		engine:    engine,
		validator: validator,
		logger:    logger,
	}
}

func (p *StdioProxy) Run() error {
	cmd := exec.Command(p.upstream[0], p.upstream[1:]...)
	cmd.Stderr = os.Stderr

	upstreamIn, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("stdin pipe: %w", err)
	}
	upstreamOut, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start upstream: %w", err)
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 2)

	pendingCalls := &sync.Map{}

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := p.agentToUpstream(os.Stdin, upstreamIn, pendingCalls); err != nil {
			errCh <- fmt.Errorf("agent->upstream: %w", err)
		}
		upstreamIn.Close()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := p.upstreamToAgent(upstreamOut, os.Stdout, pendingCalls); err != nil {
			errCh <- fmt.Errorf("upstream->agent: %w", err)
		}
	}()

	wg.Wait()
	close(errCh)

	if waitErr := cmd.Wait(); waitErr != nil {
		return fmt.Errorf("upstream exit: %w", waitErr)
	}

	for e := range errCh {
		return e
	}
	return nil
}

func (p *StdioProxy) agentToUpstream(r io.Reader, w io.Writer, pending *sync.Map) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		msg, err := jsonrpc.Decode(line)
		if err != nil {
			if _, writeErr := fmt.Fprintf(w, "%s\n", line); writeErr != nil {
				return writeErr
			}
			continue
		}

		if msg.IsRequest() && msg.Method == "tools/call" {
			toolName := extractToolName(msg.Params)
			if toolName != "" && !p.engine.Check(p.agent, toolName) {
				p.logger.Printf("DENY agent=%s tool=%s", p.agent, toolName)
				errResp := jsonrpc.ErrorResponse(msg.ID, -32600, fmt.Sprintf("nockguard: tool %q denied by policy", toolName))
				if _, writeErr := fmt.Fprintf(os.Stdout, "%s\n", errResp); writeErr != nil {
					return writeErr
				}
				continue
			}

			// Phase 2: input validation on the tool-call arguments.
			if p.validator.Enabled() {
				if hit := p.validator.CheckParams(msg.Params); hit != "" {
					p.logger.Printf("BLOCK agent=%s tool=%s rule=%s", p.agent, toolName, hit)
					errResp := jsonrpc.ErrorResponse(msg.ID, -32600, fmt.Sprintf("nockguard: tool %q arguments blocked by input validation (%s)", toolName, hit))
					if _, writeErr := fmt.Fprintf(os.Stdout, "%s\n", errResp); writeErr != nil {
						return writeErr
					}
					continue
				}
			}
			p.logger.Printf("ALLOW agent=%s tool=%s", p.agent, toolName)
		}

		if msg.IsRequest() && msg.Method == "tools/list" {
			pending.Store(string(msg.ID), true)
		}

		if _, writeErr := fmt.Fprintf(w, "%s\n", line); writeErr != nil {
			return writeErr
		}
	}
	return scanner.Err()
}

func (p *StdioProxy) upstreamToAgent(r io.Reader, w io.Writer, pending *sync.Map) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		msg, err := jsonrpc.Decode(line)
		if err != nil {
			if _, writeErr := fmt.Fprintf(w, "%s\n", line); writeErr != nil {
				return writeErr
			}
			continue
		}

		if msg.IsResponse() && msg.ID != nil {
			if _, loaded := pending.LoadAndDelete(string(msg.ID)); loaded {
				filtered := p.filterToolListResponse(line)
				if filtered != nil {
					line = filtered
				}
			}
		}

		if _, writeErr := fmt.Fprintf(w, "%s\n", line); writeErr != nil {
			return writeErr
		}
	}
	return scanner.Err()
}

func (p *StdioProxy) filterToolListResponse(line []byte) []byte {
	var resp struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  *struct {
			Tools []struct {
				Name        string          `json:"name"`
				Description string          `json:"description,omitempty"`
				InputSchema json.RawMessage `json:"inputSchema,omitempty"`
			} `json:"tools"`
		} `json:"result,omitempty"`
	}
	if err := json.Unmarshal(line, &resp); err != nil || resp.Result == nil {
		return nil
	}

	var filtered []struct {
		Name        string          `json:"name"`
		Description string          `json:"description,omitempty"`
		InputSchema json.RawMessage `json:"inputSchema,omitempty"`
	}
	for _, t := range resp.Result.Tools {
		if p.engine.Check(p.agent, t.Name) {
			filtered = append(filtered, t)
		} else {
			p.logger.Printf("HIDE agent=%s tool=%s", p.agent, t.Name)
		}
	}

	resp.Result.Tools = filtered
	out, err := json.Marshal(resp)
	if err != nil {
		return nil
	}
	return out
}

func extractToolName(params json.RawMessage) string {
	var p struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return ""
	}
	return p.Name
}
