# polyglot/python/permission_mapper.py

import json
from typing import Dict, List, Any, Optional
from collections import defaultdict

class PermissionMapper:
    def __init__(self):
        self.permission_graph: Dict[str, Dict[str, List[str]]] = defaultdict(
            lambda: {"roles": [], "resources": [], "actions": []}
        )
        self.role_to_permissions: Dict[str, List[str]] = defaultdict(list)
        self.resource_to_permissions: Dict[str, List[str]] = defaultdict(list)
        self.action_to_permissions: Dict[str, List[str]] = defaultdict(list)

    def add_permission(self, role: str, resource: str, action: str):
        """Add a permission mapping for a role on a resource with an action."""
        self.permission_graph[role]["resources"].append(resource)
        self.permission_graph[role]["actions"].append(action)
        self.role_to_permissions[role].append(f"{resource}:{action}")
        self.resource_to_permissions[resource].append(f"{role}:{action}")
        self.action_to_permissions[action].append(f"{role}:{resource}")

    def get_permissions_by_role(self, role: str) -> List[str]:
        """Get all permissions assigned to a role."""
        return self.role_to_permissions.get(role, [])

    def get_permissions_by_resource(self, resource: str) -> List[str]:
        """Get all permissions for a specific resource."""
        return self.resource_to_permissions.get(resource, [])

    def get_permissions_by_action(self, action: str) -> List[str]:
        """Get all permissions for a specific action."""
        return self.action_to_permissions.get(action, [])

    def build_permission_graph(self) -> Dict[str, Dict[str, List[str]]]:
        """Return the full permission graph."""
        return self.permission_graph

    def audit_permissions(self) -> Dict[str, Any]:
        """Audit the permissions to identify potential security issues."""
        audit_report = {
            "roles": list(self.permission_graph.keys()),
            "resources": list(self.resource_to_permissions.keys()),
            "actions": list(self.action_to_permissions.keys()),
            "permissions": self.role_to_permissions,
            "security_risks": []
        }

        # Check for roles with excessive permissions
        for role, perms in self.role_to_permissions.items():
            if len(perms) > 10:
                audit_report["security_risks"].append({
                    "type": "excessive_permissions",
                    "role": role,
                    "permissions_count": len(perms)
                })

        # Check for resources with multiple roles
        for resource, perms in self.resource_to_permissions.items():
            if len(perms) > 3:
                audit_report["security_risks"].append({
                    "type": "multiple_roles_on_resource",
                    "resource": resource,
                    "roles_count": len(perms)
                })

        # Check for actions with multiple roles
        for action, perms in self.action_to_permissions.items():
            if len(perms) > 3:
                audit_report["security_risks"].append({
                    "type": "multiple_roles_on_action",
                    "action": action,
                    "roles_count": len(perms)
                })

        return audit_report

    def load_from_file(self, file_path: str):
        """Load permission mappings from a JSON file."""
        try:
            with open(file_path, "r") as f:
                data = json.load(f)
                for role, perms in data.get("permissions", {}).items():
                    for perm in perms:
                        resource, action = perm.split(":")
                        self.add_permission(role, resource, action)
        except Exception as e:
            print(f"Error loading permissions from {file_path}: {e}")

    def save_to_file(self, file_path: str):
        """Save permission mappings to a JSON file."""
        try:
            with open(file_path, "w") as f:
                json.dump({
                    "permissions": self.role_to_permissions
                }, f, indent=2)
        except Exception as e:
            print(f"Error saving permissions to {file_path}: {e}")


if __name__ == "__main__":
    # Example usage of the PermissionMapper
    mapper = PermissionMapper()

    # Add some sample permissions
    mapper.add_permission("admin", "user", "read")
    mapper.add_permission("admin", "user", "write")
    mapper.add_permission("guest", "user", "read")
    mapper.add_permission("admin", "database", "query")
    mapper.add_permission("admin", "database", "update")

    # Output the permission graph
    print("Permission Graph:")
    print(json.dumps(mapper.build_permission_graph(), indent=2))

    # Audit permissions for security risks
    audit = mapper.audit_permissions()
    print("\nAudit Report:")
    print(json.dumps(audit, indent=2))