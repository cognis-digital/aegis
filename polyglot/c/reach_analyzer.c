#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Simulated data structures for demonstration
typedef struct {
    char *username;
    char *role;
    char *access_level;
} User;

typedef struct {
    char *endpoint;
    char *method;
    char *permission;
} AccessRule;

// Simulated user and access rules
User users[] = {
    {"admin", "admin", "full"},
    {"user1", "user", "read"},
    {"user2", "user", "write"}
};

AccessRule access_rules[] = {
    {"api/data", "GET", "read"},
    {"api/data", "POST", "write"},
    {"api/config", "PUT", "admin"}
};

// Function to check if a user has access to an endpoint
int has_access(User *user, AccessRule *rule) {
    if (strcmp(user->username, "admin") == 0 && strcmp(rule->permission, "admin") == 0) {
        return 1;
    }
    if (strcmp(user->role, rule->permission) == 0) {
        return 1;
    }
    return 0;
}

// Function to simulate reach analysis
void analyze_reach(User *user, AccessRule *rule) {
    if (has_access(user, rule)) {
        printf("User %s has access to endpoint %s via %s method.\n", user->username, rule->endpoint, rule->method);
    } else {
        printf("User %s does not have access to endpoint %s via %s method.\n", user->username, rule->endpoint, rule->method);
    }
}

// Main function with demo
int main() {
    int i, j;

    // Demo: Analyze reach for all users and rules
    printf("=== Reach Analysis ===\n");
    for (i = 0; i < sizeof(users) / sizeof(User); i++) {
        for (j = 0; j < sizeof(access_rules) / sizeof(AccessRule); j++) {
            analyze_reach(&users[i], &access_rules[j]);
        }
    }

    return 0;
}