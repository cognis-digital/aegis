#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <regex>

// Credential Scanner Class
class CredentialScanner {
public:
    // Constructor
    CredentialScanner(const std::string& filePath) : filePath_(filePath) {}

    // Scan for credentials in the file
    void scan() {
        std::ifstream file(filePath_);
        if (!file.is_open()) {
            std::cerr << "Error: Could not open file \"" << filePath_ << "\"\n";
            return;
        }

        std::string line;
        std::vector<std::string> credentials;

        // Regular expressions for different credential patterns
        std::regex usernameRegex(R"((?:username|usr|user)[^\s=]+=[^\s,]+)");
        std::regex passwordRegex(R"((?:password|pwd|pass)[^\s=]+=[^\s,]+)");
        std::regex apiKeyRegex(R"((?:api_key|apikey|token)[^\s=]+=[^\s,]+)");
        std::regex dbConfigRegex(R"((?:db_config|database|conn_str)[^\s=]+=[^\s,]+)");

        while (std::getline(file, line)) {
            // Check for username patterns
            std::smatch usernameMatch;
            if (std::regex_search(line, usernameMatch, usernameRegex)) {
                credentials.push_back(usernameMatch.str());
            }

            // Check for password patterns
            std::smatch passwordMatch;
            if (std::regex_search(line, passwordMatch, passwordRegex)) {
                credentials.push_back(passwordMatch.str());
            }

            // Check for API key patterns
            std::smatch apiKeyMatch;
            if (std::regex_search(line, apiKeyMatch, apiKeyRegex)) {
                credentials.push_back(apiKeyMatch.str());
            }

            // Check for database config patterns
            std::smatch dbConfigMatch;
            if (std::regex_search(line, dbConfigMatch, dbConfigRegex)) {
                credentials.push_back(dbConfigMatch.str());
            }
        }

        // Output results
        if (!credentials.empty()) {
            std::cout << "Credentials found in \"" << filePath_ << "\":\n";
            for (const auto& cred : credentials) {
                std::cout << "  " << cred << "\n";
            }
        } else {
            std::cout << "No credentials found in \"" << filePath_ << "\".\n";
        }
    }

private:
    std::string filePath_;
};

// Main entry point
int main() {
    // Example usage: scan a sample file for credentials
    CredentialScanner scanner("sample_config.txt");
    scanner.scan();

    return 0;
}