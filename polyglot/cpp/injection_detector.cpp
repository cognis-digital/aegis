#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>

// Forward declarations
class InjectionDetector;
class CredentialStore;
class AccessGraph;

// Base class for injection types
class InjectionType {
public:
    virtual ~InjectionType() = default;
    virtual std::string name() const = 0;
    virtual bool detect(const std::string& input) const = 0;
};

// Concrete injection type: SQL Injection
class SqlInjection : public InjectionType {
public:
    std::string name() const override { return "SQL Injection"; }
    bool detect(const std::string& input) const override {
        static const std::vector<std::string> patterns = {
            "SELECT", "UPDATE", "DELETE", "INSERT", "DROP", "ALTER",
            "'", "\"", "--", ";", "OR", "AND", "WHERE", "FROM", "JOIN"
        };
        for (const auto& pattern : patterns) {
            if (input.find(pattern) != std::string::npos) {
                return true;
            }
        }
        return false;
    }
};

// Concrete injection type: XSS
class XssInjection : public InjectionType {
public:
    std::string name() const override { return "XSS Injection"; }
    bool detect(const std::string& input) const override {
        static const std::vector<std::string> patterns = {
            "<script>", "</script>", "<img", "<a", "<div", "<span",
            "'", "\"", "onerror=", "onclick=", "onload="
        };
        for (const auto& pattern : patterns) {
            if (input.find(pattern) != std::string::npos) {
                return true;
            }
        }
        return false;
    }
};

// Concrete injection type: Command Injection
class CommandInjection : public InjectionType {
public:
    std::string name() const override { return "Command Injection"; }
    bool detect(const std::string& input) const override {
        static const std::vector<std::string> patterns = {
            ";", "|", "&", "(", ")", "{", "}", "[", "]", "$", "`",
            "&&", "||", ">", "<", "<<", ">>", "!", "(", ")", "exec"
        };
        for (const auto& pattern : patterns) {
            if (input.find(pattern) != std::string::npos) {
                return true;
            }
        }
        return false;
    }
};

// InjectionDetector class
class InjectionDetector {
public:
    InjectionDetector() {
        registerInjectionType(std::make_shared<SqlInjection>());
        registerInjectionType(std::make_shared<XssInjection>());
        registerInjectionType(std::make_shared<CommandInjection>());
    }

    void registerInjectionType(std::shared_ptr<InjectionType> type) {
        injectionTypes_[type->name()] = type;
    }

    std::vector<std::string> detectInjections(const std::string& input) const {
        std::vector<std::string> results;
        for (const auto& pair : injectionTypes_) {
            if (pair.second->detect(input)) {
                results.push_back(pair.first);
            }
        }
        return results;
    }

private:
    std::unordered_map<std::string, std::shared_ptr<InjectionType>> injectionTypes_;
};

// CredentialStore class
class CredentialStore {
public:
    void addCredential(const std::string& username, const std::string& password) {
        credentials_[username] = password;
    }

    bool validateCredential(const std::string& username, const std::string& password) const {
        auto it = credentials_.find(username);
        if (it != credentials_.end()) {
            return it->second == password;
        }
        return false;
    }

private:
    std::unordered_map<std::string, std::string> credentials_;
};

// AccessGraph class
class AccessGraph {
public:
    void addAccess(const std::string& user, const std::string& resource) {
        accessMap_[user].insert(resource);
    }

    bool hasAccess(const std::string& user, const std::string& resource) const {
        auto it = accessMap_.find(user);
        if (it != accessMap_.end()) {
            return it->second.find(resource) != it->second.end();
        }
        return false;
    }

private:
    std::unordered_map<std::string, std::unordered_set<std::string>> accessMap_;
};

// Main class for the AI Agent Permission & Access Auditor
class AegisAuditor {
public:
    AegisAuditor() : injectionDetector_(new InjectionDetector()), credentialStore_(new CredentialStore()), accessGraph_(new AccessGraph()) {}

    void addCredential(const std::string& username, const std::string& password) {
        credentialStore_->addCredential(username, password);
    }

    bool validateCredential(const std::string& username, const std::string& password) const {
        return credentialStore_->validateCredential(username, password);
    }

    void addAccess(const std::string& user, const std::string& resource) {
        accessGraph_->addAccess(user, resource);
    }

    bool hasAccess(const std::string& user, const std::string& resource) const {
        return accessGraph_->hasAccess(user, resource);
    }

    std::vector<std::string> detectInjections(const std::string& input) const {
        return injectionDetector_->detectInjections(input);
    }

private:
    std::unique_ptr<InjectionDetector> injectionDetector_;
    std::unique_ptr<CredentialStore> credentialStore_;
    std::unique_ptr<AccessGraph> accessGraph_;
};

// Entry point
int main() {
    AegisAuditor auditor;

    // Add credentials
    auditor.addCredential("admin", "securePass123");
    auditor.addCredential("user1", "pass123");

    // Add access rights
    auditor.addAccess("admin", "database");
    auditor.addAccess("admin", "api");
    auditor.addAccess("user1", "dashboard");

    // Simulate input for injection detection
    std::string input = "SELECT * FROM users WHERE username = 'admin' AND password = 'securePass123'; DROP TABLE users;";

    // Detect injections
    std::vector<std::string> injections = auditor.detectInjections(input);

    if (!injections.empty()) {
        std::cout << "Injection detected: ";
        for (const auto& inj : injections) {
            std::cout << inj << " ";
        }
        std::cout << std::endl;
    } else {
        std::cout << "No injections detected." << std::endl;
    }

    // Validate credentials
    if (auditor.validateCredential("admin", "securePass123")) {
        std::cout << "Credential 'admin' is valid." << std::endl;
    } else {
        std::cout << "Credential 'admin' is invalid." << std::endl;
    }

    // Check access
    if (auditor.hasAccess("admin", "database")) {
        std::cout << "User 'admin' has access to database." << std::endl;
    } else {
        std::cout << "User 'admin' does not have access to database." << std::endl;
    }

    return 0;
}