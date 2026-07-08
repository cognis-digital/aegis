package polyglot.java;

import java.util.*;

public class PermissionMapper {
    private final Map<String, Set<String>> userPermissions = new HashMap<>();
    private final Set<String> vulnerableEndpoints = new HashSet<>();

    public PermissionMapper() {
        // Initialize with some default data for demonstration
        initializeDefaultData();
    }

    private void initializeDefaultData() {
        // Simulate user permissions
        userPermissions.put("user1", Set.of("read:reports", "write:logs"));
        userPermissions.put("user2", Set.of("read:users", "delete:users"));

        // Simulate vulnerable endpoints (e.g., endpoints with SQL injection or XSS)
        vulnerableEndpoints.add("/api/users");
        vulnerableEndpoints.add("/api/reports");
    }

    public void mapPermissions() {
        System.out.println("=== Permission Mapper Report ===");
        for (Map.Entry<String, Set<String>> entry : userPermissions.entrySet()) {
            String user = entry.getKey();
            Set<String> perms = entry.getValue();

            System.out.println("\nUser: " + user);
            System.out.println("Permissions:");
            for (String perm : perms) {
                System.out.println(" - " + perm);

                // Check if permission overlaps with vulnerable endpoints
                if (vulnerableEndpoints.stream().anyMatch(perm::contains)) {
                    System.out.println("   ⚠️ This permission may expose a vulnerable endpoint.");
                }
            }
        }

        System.out.println("\n=== End of Report ===");
    }

    public static void main(String[] args) {
        PermissionMapper mapper = new PermissionMapper();
        mapper.mapPermissions();
    }
}