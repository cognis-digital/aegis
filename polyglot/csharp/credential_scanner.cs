using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;

namespace Aegis.CredentialScanner
{
    class Program
    {
        // Regular expressions for common credential patterns
        private static readonly Regex UsernamePattern = new Regex(@"\b(?:username|user|login)\s*=\s*['""]?([^'"\s,]+)['""]?", RegexOptions.IgnoreCase);
        private static readonly Regex PasswordPattern = new Regex(@"\b(?:password|pass|secret|token)\s*=\s*['""]?([^'"\s,]+)['""]?", RegexOptions.IgnoreCase);
        private static readonly Regex ApiKeyPattern = new Regex(@"\b(?:api_key|access_key|secret_key)\s*=\s*['""]?([^'"\s,]+)['""]?", RegexOptions.IgnoreCase);
        private static readonly Regex ConfigPattern = new Regex(@"\b(?:config|credentials|auth)\s*=\s*['""]?([^'"\s,]+)['""]?", RegexOptions.IgnoreCase);

        // List of common credential files to scan
        private static readonly string[] CredentialFiles = {
            "appsettings.json",
            "web.config",
            "connectionstrings.config",
            "credentials.yaml",
            "env",
            "secrets.env",
            "config.json",
            "database.ini",
            "auth.properties"
        };

        // List of common injection patterns
        private static readonly Regex InjectionPattern = new Regex(@"\b(?:eval|exec|system|shell_exec|passthru|pcntl_exec|preg_replace|mysql_query|pg_query|sqlsrv_query|mysqli_query)\s*$$[^$$]*$$", RegexOptions.IgnoreCase);

        // List of common reach patterns (e.g., remote code execution)
        private static readonly Regex ReachPattern = new Regex(@"\b(?:remote_code_execution|rcs|execute|call|invoke|eval|system|shell_exec|passthru|pcntl_exec|preg_replace|mysql_query|pg_query|sqlsrv_query|mysqli_query)\s*$$[^$$]*$$", RegexOptions.IgnoreCase);

        static void Main(string[] args)
        {
            Console.WriteLine("=== Aegis Credential Scanner ===");
            Console.WriteLine("Scanning for credentials, injection points, and reach patterns...");

            var results = new List<string>();

            // Scan files
            foreach (var file in CredentialFiles)
            {
                if (File.Exists(file))
                {
                    string content = File.ReadAllText(file);
                    ScanContent(content, results);
                }
            }

            // Check for injection and reach patterns in code
            string codeContent = GetCodeContent();
            ScanContent(codeContent, results);

            // Output results
            if (results.Count == 0)
            {
                Console.WriteLine("No credentials, injection points, or reach patterns found.");
            }
            else
            {
                Console.WriteLine("Found potential security issues:");
                foreach (var result in results)
                {
                    Console.WriteLine("- " + result);
                }
            }
        }

        private static void ScanContent(string content, List<string> results)
        {
            // Check for credentials
            var matches = UsernamePattern.Matches(content);
            if (matches.Count > 0)
            {
                results.Add($"Credential found: Username '{matches[0].Groups[1].Value}' in file.");
            }

            matches = PasswordPattern.Matches(content);
            if (matches.Count > 0)
            {
                results.Add($"Credential found: Password '{matches[0].Groups[1].Value}' in file.");
            }

            matches = ApiKeyPattern.Matches(content);
            if (matches.Count > 0)
            {
                results.Add($"Credential found: API Key '{matches[0].Groups[1].Value}' in file.");
            }

            matches = ConfigPattern.Matches(content);
            if (matches.Count > 0)
            {
                results.Add($"Credential found: Configuration value '{matches[0].Groups[1].Value}' in file.");
            }

            // Check for injection
            matches = InjectionPattern.Matches(content);
            foreach (Match match in matches)
            {
                results.Add($"Potential injection point: {match.Value}");
            }

            // Check for reach patterns
            matches = ReachPattern.Matches(content);
            foreach (Match match in matches)
            {
                results.Add($"Potential reach pattern: {match.Value}");
            }
        }

        private static string GetCodeContent()
        {
            // Simulate code content for demonstration
            return @"
using System;
class Program
{
    static void Main()
    {
        string input = Console.ReadLine();
        var result = eval(input);
        Console.WriteLine(result);
    }
}
";
        }
    }
}