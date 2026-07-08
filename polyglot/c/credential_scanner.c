#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_LINE 1024
#define MAX_FILES 100

typedef struct {
    char *filename;
    int line_number;
    char *line;
} FileLine;

// Function to check if a string contains credentials (simple pattern matching)
int contains_credentials(const char *str) {
    // Simple heuristic: look for common credential patterns
    // This is a basic example; real use would include more sophisticated checks
    const char *patterns[] = {
        "password", "passwd", "token", "secret", "key", "api_key",
        "username", "user", "pass", "cred", "auth"
    };
    int i;
    for (i = 0; i < sizeof(patterns)/sizeof(patterns[0]); i++) {
        if (strstr(str, patterns[i])) {
            return 1;
        }
    }
    return 0;
}

// Function to read a file and check for credentials
void scan_file(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("fopen");
        return;
    }

    char line[MAX_LINE];
    int line_number = 0;

    while (fgets(line, sizeof(line), file)) {
        line_number++;
        if (contains_credentials(line)) {
            printf("Credential found in %s at line %d:\n%s", filename, line_number, line);
        }
    }

    fclose(file);
}

// Function to scan multiple files
void scan_files(const char *filenames[], int count) {
    for (int i = 0; i < count; i++) {
        scan_file(filenames[i]);
    }
}

// Main function with demo
int main() {
    // Demo: scan some example files
    const char *demo_files[] = {
        "example1.c",
        "example2.h",
        "example3.txt"
    };

    // Simulate the existence of these files by creating them in memory
    FILE *temp_files[3];
    char *file_contents[] = {
        "#include <stdio.h>\nint main() { printf(\"Hello, world!\"); return 0; }",
        "typedef struct { char *username; char *password; } User;",
        "This is a test file with password123 and secret_key."
    };

    for (int i = 0; i < 3; i++) {
        temp_files[i] = tmpfile();
        if (!temp_files[i]) {
            perror("tmpfile");
            return 1;
        }
        fprintf(temp_files[i], "%s", file_contents[i]);
        fseek(temp_files[i], 0, SEEK_SET);
        scan_file(temp_files[i]);
        fclose(temp_files[i]);
    }

    // Scan actual files if provided as command-line arguments
    int argc = 3;
    char *argv[] = {"credential_scanner", "example1.c", "example2.h"};
    scan_files(argv + 1, argc - 1);

    return 0;
}