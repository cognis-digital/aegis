#include <iostream>
#include <vector>
#include <string>
#include <unordered_map>
#include <memory>

// Forward declarations
class AccessNode;
class ReachAnalyzer;

// Represents a node in the access graph
class AccessNode {
public:
    std::string id;
    std::string type; // e.g., "user", "service", "resource"
    std::vector<std::shared_ptr<AccessNode>> children;

    AccessNode(const std::string& node_id, const std::string& node_type)
        : id(node_id), type(node_type) {}

    void addChild(std::shared_ptr<AccessNode> child) {
        children.push_back(child);
    }

    friend class ReachAnalyzer;
};

// Analyzes reachability in the access graph
class ReachAnalyzer {
public:
    // Build a simple access graph for demonstration
    static std::shared_ptr<AccessNode> buildDemoGraph() {
        auto root = std::make_shared<AccessNode>("root", "system");
        auto user1 = std::make_shared<AccessNode>("user1", "user");
        auto serviceA = std::make_shared<AccessNode>("serviceA", "service");
        auto resourceX = std::make_shared<AccessNode>("resourceX", "resource");

        root->addChild(user1);
        user1->addChild(serviceA);
        serviceA->addChild(resourceX);

        return root;
    }

    // Analyze reachability from a starting node
    static void analyzeReachability(const std::shared_ptr<AccessNode>& start, const std::string& target_id) {
        std::unordered_map<std::string, bool> visited;
        std::vector<std::shared_ptr<AccessNode>> queue;

        queue.push_back(start);
        visited[start->id] = true;

        while (!queue.empty()) {
            auto current = queue.back();
            queue.pop_back();

            if (current->id == target_id) {
                std::cout << "Reachable: " << target_id << " is reachable from " << start->id << std::endl;
                return;
            }

            for (const auto& child : current->children) {
                if (!visited.count(child->id)) {
                    visited[child->id] = true;
                    queue.push_back(child);
                }
            }
        }

        std::cout << "Not Reachable: " << target_id << " is not reachable from " << start->id << std::endl;
    }
};

// Main entry point
int main() {
    // Build the demo access graph
    auto graph = ReachAnalyzer::buildDemoGraph();

    // Analyze reachability from root to various nodes
    ReachAnalyzer::analyzeReachability(graph, "user1");
    ReachAnalyzer::analyzeReachability(graph, "serviceA");
    ReachAnalyzer::analyzeReachability(graph, "resourceX");
    ReachAnalyzer::analyzeReachability(graph, "nonexistent");

    return 0;
}