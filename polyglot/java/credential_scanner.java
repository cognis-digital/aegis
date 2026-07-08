import java.io.*;
import java.nio.file.*;
import java.util.*;

public class credential_scanner {
    private static final Set<String> CREDENTIAL_KEYWORDS = new HashSet<>(Arrays.asList(
        "username", "password", "token", "secret", "key", "cred", "auth", "api_key", "bearer_token"
    ));

    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Usage: java credential_scanner <directory>");
            return;
        }

        String directoryPath = args[0];
        try {
            scanDirectory(directoryPath);
        } catch (IOException e) {
            System.err.println("Error scanning directory: " + e.getMessage());
        }
    }

    private static void scanDirectory(String directoryPath) throws IOException {
        Files.walk(Paths.get(directoryPath))
             .filter(path -> Files.isRegularFile(path))
             .forEach(path -> {
                 try {
                     scanFile(path);
                 } catch (IOException e) {
                     System.err.println("Error scanning file: " + path + " - " + e.getMessage());
                 }
             });
    }

    private static void scanFile(Path filePath) throws IOException {
        List<String> lines = Files.readAllLines(filePath);
        boolean foundCredentials = false;

        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i);
            if (line.trim().isEmpty()) continue;

            for (String keyword : CREDENTIAL_KEYWORDS) {
                if (line.toLowerCase().contains(keyword)) {
                    int startIdx = line.toLowerCase().indexOf(keyword);
                    int endIdx = startIdx + keyword.length();
                    String context = line.substring(Math.max(0, startIdx - 50), Math.min(endIdx + 50, line.length()));
                    System.out.println("Potential credential found in file: " + filePath);
                    System.out.println("Line " + (i + 1) + ": " + context);
                    foundCredentials = true;
                }
            }
        }

        if (foundCredentials) {
            System.out.println("File " + filePath + " may contain credentials.");
        }
    }
}