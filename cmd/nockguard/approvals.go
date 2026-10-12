package main

import (
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/nocktechnologies/nockguard/internal/approval"
)

// runApprovals is the operator side of the local approver: list held calls and
// approve or deny them. It shows id, agent, tool, reason and age — never arguments.
func runApprovals(args []string) int {
	dir, err := approval.DefaultLocalDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, "approvals:", err)
		return 1
	}
	switch {
	case len(args) == 1 && args[0] == "list":
		held, err := approval.ListPending(dir)
		if err != nil {
			fmt.Fprintln(os.Stderr, "approvals:", err)
			return 1
		}
		if len(held) == 0 {
			fmt.Println("no pending calls")
			return 0
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tAGENT\tTOOL\tREASON\tAGE")
		for _, h := range held {
			fmt.Fprintf(w, "%s\t%q\t%q\t%q\t%s\n", h.ID, h.Agent, h.Tool, h.Reason, time.Duration(h.AgeSec)*time.Second)
		}
		w.Flush()
		return 0
	case len(args) == 2 && (args[0] == "approve" || args[0] == "deny"):
		if err := approval.Decide(dir, args[1], args[0] == "approve"); err != nil {
			fmt.Fprintln(os.Stderr, "approvals:", err)
			return 1
		}
		fmt.Printf("%s %s\n", args[0], args[1])
		return 0
	}
	fmt.Fprintln(os.Stderr, "usage: nockguard approvals (list | approve <id> | deny <id>)")
	return 1
}
