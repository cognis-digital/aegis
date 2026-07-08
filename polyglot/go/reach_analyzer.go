package main

import (
	"fmt"
	"os"
	"strings"
)

// ReachAnalyzer analyzes the reach of an AI agent's access.
type ReachAnalyzer struct {
	accessMap map[string][]string // key: resource, value: accessible agents
}

// NewReachAnalyzer creates a new instance with initial access data.
func NewReachAnalyzer(initialAccess map[string][]string) *ReachAnalyzer {
	return &ReachAnalyzer{
		accessMap: initialAccess,
	}
}

// AnalyzeReach analyzes the reach of an agent across resources.
func (ra *ReachAnalyzer) AnalyzeReach(agent string) ([]string, error) {
	var reachableResources []string
	for resource, agents := range ra.accessMap {
		for _, a := range agents {
			if a == agent {
				reachableResources = append(reachableResources, resource)
				break
			}
		}
	}
	return reachableResources, nil
}

// AddAccess adds new access relationships.
func (ra *ReachAnalyzer) AddAccess(resource string, agents []string) {
	if ra.accessMap == nil {
		ra.accessMap = make(map[string][]string)
	}
	ra.accessMap[resource] = append(ra.accessMap[resource], agents...)
}

// PrintReach prints the reach of an agent.
func (ra *ReachAnalyzer) PrintReach(agent string) {
	reachable, _ := ra.AnalyzeReach(agent)
	if len(reachable) == 0 {
		fmt.Printf("Agent %s has no reachable resources.\n", agent)
	} else {
		fmt.Printf("Agent %s can reach the following resources:\n")
		for _, r := range reachable {
			fmt.Printf("- %s\n", r)
		}
	}
}

func main() {
	// Example usage of ReachAnalyzer
	initialAccess := map[string][]string{
		"database": {"admin", "ai_agent_1"},
		"api":      {"ai_agent_1", "ai_agent_2"},
		"storage":  {"admin", "ai_agent_2"},
	}

	ra := NewReachAnalyzer(initialAccess)

	// Demo: Analyze reach of ai_agent_1
	fmt.Println("Analyzing reach for ai_agent_1:")
	reachable, _ := ra.AnalyzeReach("ai_agent_1")
	for _, r := range reachable {
		fmt.Printf("- %s\n", r)
	}

	// Demo: Add new access and analyze again
	ra.AddAccess("queue", []string{"ai_agent_1"})
	fmt.Println("\nAnalyzing reach for ai_agent_1 after adding queue access:")
	reachable, _ = ra.AnalyzeReach("ai_agent_1")
	for _, r := range reachable {
		fmt.Printf("- %s\n", r)
	}

	// Demo: Print reach for ai_agent_2
	fmt.Println("\nPrinting reach for ai_agent_2:")
	ra.PrintReach("ai_agent_2")
}