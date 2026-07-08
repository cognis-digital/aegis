#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>
#include <mutex>
#include <thread>
#include <atomic>
#include <chrono>

// Simulated session data structure
struct Session {
    std::string id;
    std::string user;
    std::string role;
    std::string lastActivity;
    bool active;
};

// Simulated credential store
struct Credential {
    std::string username;
    std::string password;
    std::string token;
};

// Simulated injection point
struct InjectionPoint {
    std::string name;
    std::string type;
    std::string source;
};

// Simulated reachability data
struct Reachability {
    std::string endpoint;
    std::string protocol;
    std::string origin;
    bool reachable;
};

class SessionMonitor {
public:
    SessionMonitor() : sessionMap(), credentialStore(), injectionPoints(), reachabilityMap(), activeSessions(0), monitorRunning(true) {}

    void startMonitoring() {
        std::thread([this]() {
            while (monitorRunning) {
                checkActiveSessions();
                checkCredentials();
                checkInjections();
                checkReachability();
                std::this_thread::sleep_for(std::chrono::seconds(5));
            }
        }).detach();
    }

    void addSession(const Session& session) {
        std::lock_guard<std::mutex> lock(sessionMutex);
        sessionMap[session.id] = session;
        activeSessions++;
    }

    void removeSession(const std::string& sessionId) {
        std::lock_guard<std::mutex> lock(sessionMutex);
        auto it = sessionMap.find(sessionId);
        if (it != sessionMap.end()) {
            activeSessions--;
            sessionMap.erase(it);
        }
    }

    void addCredential(const Credential& credential) {
        std::lock_guard<std::mutex> lock(credentialMutex);
        credentialStore[credential.username] = credential;
    }

    void addInjectionPoint(const InjectionPoint& point) {
        std::lock_guard<std::mutex> lock(injectionMutex);
        injectionPoints.push_back(point);
    }

    void addReachability(const Reachability& reach) {
        std::lock_guard<std::mutex> lock(reachMutex);
        reachabilityMap[reach.endpoint] = reach;
    }

    void checkActiveSessions() {
        std::lock_guard<std::mutex> lock(sessionMutex);
        for (auto& [id, session] : sessionMap) {
            if (session.active && isSessionAtRisk(session)) {
                std::cout << "ALERT: Session " << id << " is at risk due to credentials, injection, or reachability.\n";
            }
        }
    }

    void checkCredentials() {
        std::lock_guard<std::mutex> lock(credentialMutex);
        for (auto& [username, cred] : credentialStore) {
            if (isCredentialCompromised(cred)) {
                std::cout << "ALERT: Credential for user " << username << " is compromised.\n";
            }
        }
    }

    void checkInjections() {
        std::lock_guard<std::mutex> lock(injectionMutex);
        for (const auto& point : injectionPoints) {
            if (isInjectionVulnerable(point)) {
                std::cout << "ALERT: Injection point " << point.name << " is vulnerable.\n";
            }
        }
    }

    void checkReachability() {
        std::lock_guard<std::mutex> lock(reachMutex);
        for (auto& [endpoint, reach] : reachabilityMap) {
            if (!reach.reachable && isReachableCritical(reach)) {
                std::cout << "ALERT: Endpoint " << endpoint << " is unreachable and critical.\n";
            }
        }
    }

private:
    std::unordered_map<std::string, Session> sessionMap;
    std::unordered_map<std::string, Credential> credentialStore;
    std::vector<InjectionPoint> injectionPoints;
    std::unordered_map<std::string, Reachability> reachabilityMap;
    std::mutex sessionMutex;
    std::mutex credentialMutex;
    std::mutex injectionMutex;
    std::mutex reachMutex;
    int activeSessions;
    std::atomic<bool> monitorRunning;

    bool isSessionAtRisk(const Session& session) {
        return isCredentialCompromised(getCredential(session.user)) || 
               isInjectionVulnerable(findInjectionPoint(session.role)) ||
               !isReachableCritical(findReachability(session.lastActivity));
    }

    Credential getCredential(const std::string& username) {
        auto it = credentialStore.find(username);
        if (it != credentialStore.end()) {
            return it->second;
        }
        return {"", "", ""};
    }

    InjectionPoint findInjectionPoint(const std::string& role) {
        for (const auto& point : injectionPoints) {
            if (point.type == role) {
                return point;
            }
        }
        return {"", "", ""};
    }

    Reachability findReachability(const std::string& activity) {
        for (auto& [endpoint, reach] : reachabilityMap) {
            if (reach.source == activity) {
                return reach;
            }
        }
        return {"", "", "", false};
    }

    bool isCredentialCompromised(const Credential& cred) {
        return !cred.username.empty() && !cred.password.empty() && !cred.token.empty();
    }

    bool isInjectionVulnerable(const InjectionPoint& point) {
        return !point.name.empty() && point.type == "SQL" || point.type == "XSS";
    }

    bool isReachableCritical(const Reachability& reach) {
        return reach.protocol == "HTTPS" && reach.origin == "external";
    }
};

int main() {
    SessionMonitor monitor;
    monitor.startMonitoring();

    // Simulate session creation
    Session s1 = {"S123", "admin", "admin", "2025-04-05T14:30:00Z", true};
    Session s2 = {"S456", "user", "viewer", "2025-04-05T14:25:00Z", true};

    monitor.addSession(s1);
    monitor.addSession(s2);

    // Simulate credential store
    Credential c1 = {"admin", "P@ssw0rd!", "abc123xyz"};
    Credential c2 = {"user", "123456", "def456uvw"};
    monitor.addCredential(c1);
    monitor.addCredential(c2);

    // Simulate injection points
    InjectionPoint ip1 = {"login_form", "SQL", "frontend"};
    InjectionPoint ip2 = {"api_endpoint", "XSS", "backend"};
    monitor.addInjectionPoint(ip1);
    monitor.addInjectionPoint(ip2);

    // Simulate reachability
    Reachability r1 = {"/api/v1/data", "HTTPS", "external", true};
    Reachability r2 = {"/admin/config", "HTTP", "internal", false};
    monitor.addReachability(r1);
    monitor.addReachability(r2);

    // Keep the main thread alive for a while to see the monitoring in action
    std::this_thread::sleep_for(std::chrono::seconds(15));

    return 0;
}