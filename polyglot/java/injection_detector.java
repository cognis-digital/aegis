import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.*;

public class InjectionDetector {
    private static final Set<String> SQL_KEYWORDS = new HashSet<>(Arrays.asList(
        "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE", "TRUNCATE",
        "UNION", "OR", "AND", "NOT", "IN", "LIKE", "BETWEEN", "CASE", "WHEN", "THEN",
        "ELSE", "ISNULL", "IF", "WHERE", "FROM", "JOIN", "ON", "HAVING", "GROUP", "ORDER"
    ));

    private static final Set<String> XSS_KEYWORDS = new HashSet<>(Arrays.asList(
        "<script>", "</script>", "<img", "<a", "<form", "<input", "<body", "<html",
        "<style>", "<meta", "<link", "<iframe", "<frame", "<table", "<tr", "<td"
    ));

    private static final Set<String> CMD_KEYWORDS = new HashSet<>(Arrays.asList(
        ";", "|", "&", "&&", "||", ">", "<", "<<", ">>", "(", ")", "{", "}", "[", "]",
        "!", "$", "`", "exec", "system", "run", "call"
    ));

    private static final Set<String> HEADER_KEYWORDS = new HashSet<>(Arrays.asList(
        "Content-Type", "Authorization", "Cookie", "User-Agent", "Referer", "Host"
    ));

    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Usage: java InjectionDetector <file_path>");
            return;
        }

        String filePath = args[0];
        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;
            int lineNumber = 0;
            while ((line = reader.readLine()) != null) {
                lineNumber++;
                detectInjections(line, lineNumber);
            }
        } catch (IOException e) {
            System.err.println("Error reading file: " + e.getMessage());
        }
    }

    private static void detectInjections(String line, int lineNumber) {
        boolean sqlDetected = false;
        boolean xssDetected = false;
        boolean cmdDetected = false;
        boolean headerDetected = false;

        // SQL Injection Detection
        for (String keyword : SQL_KEYWORDS) {
            if (line.contains(keyword)) {
                sqlDetected = true;
                break;
            }
        }

        // XSS Injection Detection
        for (String keyword : XSS_KEYWORDS) {
            if (line.contains(keyword)) {
                xssDetected = true;
                break;
            }
        }

        // Command Injection Detection
        for (String keyword : CMD_KEYWORDS) {
            if (line.contains(keyword)) {
                cmdDetected = true;
                break;
            }
        }

        // Header Injection Detection
        for (String keyword : HEADER_KEYWORDS) {
            if (line.contains(keyword)) {
                headerDetected = true;
                break;
            }
        }

        if (sqlDetected || xssDetected || cmdDetected || headerDetected) {
            System.out.println("Line " + lineNumber + ": Possible injection detected");
            if (sqlDetected) System.out.println("  - SQL Injection keywords found");
            if (xssDetected) System.out.println("  - XSS Injection keywords found");
            if (cmdDetected) System.out.println("  - Command Injection keywords found");
            if (headerDetected) System.out.println("  - Header Injection keywords found");
        }
    }
}