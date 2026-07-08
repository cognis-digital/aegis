#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

// Define supported injection types
#define INJECTION_TYPES 5
typedef enum {
    SQL_INJECTION,
    XSS_INJECTION,
    COMMAND_INJECTION,
    LDAP_INJECTION,
    JSON_INJECTION
} InjectionType;

// Helper function to check for SQL injection patterns
int is_sql_injection(const char *input) {
    const char *patterns[] = {
        "SELECT", "INSERT", "UPDATE", "DELETE",
        "DROP", "TRUNCATE", "ALTER", "CREATE",
        "'", "\"", "--", ";", "UNION", "WHERE"
    };
    int i;
    for (i = 0; i < sizeof(patterns)/sizeof(patterns[0]); i++) {
        if (strstr(input, patterns[i])) {
            return 1;
        }
    }
    return 0;
}

// Helper function to check for XSS injection patterns
int is_xss_injection(const char *input) {
    const char *patterns[] = {
        "<script>", "</script>", "alert(", "onload=", "onclick=", "onerror="
    };
    int i;
    for (i = 0; i < sizeof(patterns)/sizeof(patterns[0]); i++) {
        if (strstr(input, patterns[i])) {
            return 1;
        }
    }
    return 0;
}

// Helper function to check for command injection patterns
int is_command_injection(const char *input) {
    const char *patterns[] = {
        ";", "|", "&", "(", ")", "{", "}", "[", "]", "$", "`", "||", "&&"
    };
    int i;
    for (i = 0; i < sizeof(patterns)/sizeof(patterns[0]); i++) {
        if (strstr(input, patterns[i])) {
            return 1;
        }
    }
    return 0;
}

// Helper function to check for LDAP injection patterns
int is_ldap_injection(const char *input) {
    const char *patterns[] = {
        "(", ")", "AND", "OR", "NOT", "=", "!="
    };
    int i;
    for (i = 0; i < sizeof(patterns)/sizeof(patterns[0]); i++) {
        if (strstr(input, patterns[i])) {
            return 1;
        }
    }
    return 0;
}

// Helper function to check for JSON injection patterns
int is_json_injection(const char *input) {
    const char *patterns[] = {
        "script", "<", ">", "&", "\"", "'", "{", "}"
    };
    int i;
    for (i = 0; i < sizeof(patterns)/sizeof(patterns[0]); i++) {
        if (strstr(input, patterns[i])) {
            return 1;
        }
    }
    return 0;
}

// Main injection detection function
InjectionType detect_injection(const char *input) {
    if (is_sql_injection(input)) {
        return SQL_INJECTION;
    } else if (is_xss_injection(input)) {
        return XSS_INJECTION;
    } else if (is_command_injection(input)) {
        return COMMAND_INJECTION;
    } else if (is_ldap_injection(input)) {
        return LDAP_INJECTION;
    } else if (is_json_injection(input)) {
        return JSON_INJECTION;
    }
    return 0;
}

// Helper function to convert InjectionType to string
const char* injection_type_to_string(InjectionType type) {
    switch (type) {
        case SQL_INJECTION: return "SQL Injection";
        case XSS_INJECTION: return "XSS Injection";
        case COMMAND_INJECTION: return "Command Injection";
        case LDAP_INJECTION: return "LDAP Injection";
        case JSON_INJECTION: return "JSON Injection";
        default: return "Unknown Injection";
    }
}

// Main entry point
int main() {
    char input[1024];

    printf("Enter input to audit for injection:\n");
    if (fgets(input, sizeof(input), stdin) != NULL) {
        input[strcspn(input, "\n")] = '\0'; // Remove newline

        InjectionType result = detect_injection(input);
        const char* result_str = injection_type_to_string(result);

        if (result != 0) {
            printf("Injection detected: %s\n", result_str);
        } else {
            printf("No injection detected.\n");
        }
    } else {
        printf("Error reading input.\n");
    }

    return 0;
}