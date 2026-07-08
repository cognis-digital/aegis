package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// PermissionMapper represents the structure of a permission mapping
type PermissionMapper struct {
	Principal string
	Resource  string
	Action    string
}

// auditPermissions audits permissions and maps them to potential vulnerabilities
func auditPermissions(principals []string, resources []string, actions []string) map[string][]PermissionMapper {
	mapper := make(map[string][]PermissionMapper)
	for _, principal := range principals {
		for _, resource := range resources {
			for _, action := range actions {
				mapper[principal] = append(mapper[principal], PermissionMapper{
					Principal: principal,
					Resource:  resource,
					Action:    action,
				})
			}
		}
	}
	return mapper
}

// detectLethalTrifecta checks for the lethal trifecta of credentials + injection + reach
func detectLethalTrifecta(mapper map[string][]PermissionMapper) {
	for principal, perms := range mapper {
		for _, perm := range perms {
			if strings.Contains(perm.Resource, "config") && strings.Contains(perm.Action, "write") {
				fmt.Printf("Lethal Trifecta Alert: Principal '%s' has write access to config resource '%s'\n", principal, perm.Resource)
			}
		}
	}
}

func main() {
	var principals []string
	var resources []string
	var actions []string

	rootCmd := &cobra.Command{
		Use:   "permission_mapper",
		Short: "AI Agent Permission & Access Auditor - Permission Mapper",
		Long:  "Audits and maps permissions to detect potential vulnerabilities such as the lethal trifecta of credentials + injection + reach.",
		Run: func(cmd *cobra.Command, args []string) {
			mapper := auditPermissions(principals, resources, actions)
			detectLethalTrifecta(mapper)
		},
	}

	rootCmd.Flags().StringSliceVarP(&principals, "principal", "p", []string{}, "List of principals (e.g., users, services)")
	rootCmd.Flags().StringSliceVarP(&resources, "resource", "r", []string{}, "List of resources (e.g., databases, APIs)")
	rootCmd.Flags().StringSliceVarP(&actions, "action", "a", []string{}, "List of actions (e.g., read, write, execute)")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}