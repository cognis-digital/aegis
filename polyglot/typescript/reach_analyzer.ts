// polyglot/typescript/reach_analyzer.ts

import { Aegis } from './aegis';

// Define the structure of a system component
interface SystemComponent {
  id: string;
  name: string;
  type: string;
  dependencies: string[];
  accessPoints: string[];
}

// Define the structure of an access path
interface AccessPath {
  source: string;
  destination: string;
  path: string[];
  riskScore: number;
}

// ReachAnalyzer class to analyze reachability in a system
class ReachAnalyzer {
  private systemComponents: Map<string, SystemComponent>;
  private aegis: Aegis;

  constructor(aegis: Aegis) {
    this.aegis = aegis;
    this.systemComponents = new Map<string, SystemComponent>();
  }

  // Load system components from the Aegis tool
  loadSystemComponents(): void {
    const components = this.aegis.getSystemComponents();
    for (const component of components) {
      this.systemComponents.set(component.id, component);
    }
  }

  // Build a graph of component dependencies
  buildDependencyGraph(): Map<string, Set<string>> {
    const graph = new Map<string, Set<string>>();
    for (const [id, component] of this.systemComponents.entries()) {
      if (!graph.has(id)) {
        graph.set(id, new Set<string>());
      }
      for (const dep of component.dependencies) {
        if (!graph.has(dep)) {
          graph.set(dep, new Set<string>());
        }
        graph.get(id)?.add(dep);
      }
    }
    return graph;
  }

  // Find all reachable components from a given source
  findReachableComponents(source: string): Set<string> {
    const visited = new Set<string>();
    const queue: string[] = [source];

    while (queue.length > 0) {
      const current = queue.shift()!;
      if (visited.has(current)) continue;
      visited.add(current);
      queue.push(...Array.from(this.systemComponents.get(current)?.dependencies || []));
    }

    return visited;
  }

  // Analyze reachability and identify potential security risks
  analyzeReach(): AccessPath[] {
    const accessPaths: AccessPath[] = [];
    const graph = this.buildDependencyGraph();

    for (const [source, dependencies] of graph.entries()) {
      for (const dest of dependencies) {
        const reachable = this.findReachableComponents(source);
        if (reachable.has(dest)) {
          const path = this.findAccessPath(source, dest, graph);
          if (path && path.length > 0) {
            accessPaths.push({
              source,
              destination: dest,
              path,
              riskScore: this.calculateRiskScore(path)
            });
          }
        }
      }
    }

    return accessPaths;
  }

  // Find the actual path from source to destination
  private findAccessPath(source: string, destination: string, graph: Map<string, Set<string>>): string[] {
    const visited = new Set<string>();
    const queue: { node: string; path: string[] }[] = [{ node: source, path: [source] }];

    while (queue.length > 0) {
      const { node, path } = queue.shift()!;
      if (node === destination) {
        return path;
      }
      if (visited.has(node)) continue;
      visited.add(node);

      for (const neighbor of graph.get(node) || []) {
        queue.push({ node: neighbor, path: [...path, neighbor] });
      }
    }

    return [];
  }

  // Calculate a risk score based on the access path
  private calculateRiskScore(path: string[]): number {
    // Simple heuristic: longer paths are more risky
    const baseRisk = 10;
    const pathLength = path.length;
    const riskMultiplier = Math.min(10, pathLength - 1); // Max risk multiplier of 10
    return baseRisk + riskMultiplier;
  }

  // Run the reach analysis and output results
  run(): void {
    this.loadSystemComponents();
    const accessPaths = this.analyzeReach();

    console.log('Reach Analysis Results:');
    for (const path of accessPaths) {
      console.log(`- From: ${path.source} to ${path.destination}`);
      console.log(`  Path: ${path.path.join(' -> ')}`);
      console.log(`  Risk Score: ${path.riskScore}\n`);
    }
  }
}

// Entry point for the Reach Analyzer
const aegis = new Aegis();
const reachAnalyzer = new ReachAnalyzer(aegis);
reachAnalyzer.run();