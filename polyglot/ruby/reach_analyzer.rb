# polyglot/ruby/reach_analyzer.rb

require 'set'

class ReachAnalyzer
  attr_reader :nodes, :edges, :reachable_nodes

  def initialize(graph)
    @nodes = graph.keys
    @edges = graph
    @reachable_nodes = Set.new
  end

  def analyze(start_node)
    return false unless @nodes.include?(start_node)

    dfs(start_node)
    @reachable_nodes
  end

  private

  def dfs(node)
    return if @reachable_nodes.include?(node)

    @reachable_nodes.add(node)
    @edges[node].each do |neighbor|
      dfs(neighbor)
    end
  end
end

# Example usage
if __FILE__ == $0
  # Sample graph: nodes are access points, edges represent reachability
  graph = {
    'admin' => ['dashboard', 'api'],
    'dashboard' => ['reports', 'settings'],
    'api' => ['users', 'logs'],
    'users' => [],
    'logs' => [],
    'reports' => [],
    'settings' => []
  }

  analyzer = ReachAnalyzer.new(graph)
  start_node = 'admin'
  reachable = analyzer.analyze(start_node)

  puts "Reachable nodes from '#{start_node}':"
  puts reachable.sort.join(', ')
end