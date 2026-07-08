# polyglot/python/reach_analyzer.py

import networkx as nx
from typing import Set, Dict, List, Tuple

class ReachAnalyzer:
    def __init__(self):
        self.graph = nx.DiGraph()
        self.nodes = set()
        self.edges = set()

    def add_node(self, node: str) -> None:
        if node not in self.nodes:
            self.nodes.add(node)
            self.graph.add_node(node)

    def add_edge(self, source: str, target: str) -> None:
        if source not in self.nodes or target not in self.nodes:
            raise ValueError("Both nodes must exist in the graph")
        if (source, target) not in self.edges:
            self.edges.add((source, target))
            self.graph.add_edge(source, target)

    def analyze_reach(self, start_node: str) -> Set[str]:
        if start_node not in self.nodes:
            raise ValueError("Start node does not exist in the graph")
        return set(nx.dfs_preorder_nodes(self.graph, start_node))

    def find_all_reachable(self) -> Dict[str, Set[str]]:
        reachable = {}
        for node in self.nodes:
            reachable[node] = self.analyze_reach(node)
        return reachable

def main():
    # Example usage of ReachAnalyzer
    analyzer = ReachAnalyzer()

    # Add nodes and edges representing a simple dependency graph
    analyzer.add_node("API Gateway")
    analyzer.add_node("Auth Service")
    analyzer.add_node("Database")
    analyzer.add_node("Payment Processor")
    analyzer.add_node("Notification Service")

    analyzer.add_edge("API Gateway", "Auth Service")
    analyzer.add_edge("Auth Service", "Database")
    analyzer.add_edge("API Gateway", "Payment Processor")
    analyzer.add_edge("Payment Processor", "Database")
    analyzer.add_edge("Payment Processor", "Notification Service")
    analyzer.add_edge("Notification Service", "Database")

    # Analyze reachability from API Gateway
    reachable_nodes = analyzer.analyze_reach("API Gateway")
    print("Reachable nodes from API Gateway:", reachable_nodes)

    # Find all reachable nodes from each node
    all_reachable = analyzer.find_all_reachable()
    print("\nAll reachable nodes:")
    for node, reachable in all_reachable.items():
        print(f"{node}: {reachable}")

if __name__ == "__main__":
    main()