# polyglot/ruby/injection_detector.rb

require 'yaml'
require 'set'

class InjectionDetector
  attr_reader :results

  def initialize(input)
    @input = input
    @results = []
  end

  def run
    detect_injections
    output_results
  end

  private

  def detect_injections
    # Simulate parsing of a configuration or codebase
    config = parse_config(@input)

    # Check for SQL injection patterns
    sql_patterns = %w[
      ' OR 1=1 --
      ; DROP TABLE users; --
      --sleep(5)--
      SELECT * FROM users WHERE id = #{ 
      UNION SELECT * FROM users --
    ]

    sql_injections = config.select do |key, value|
      sql_patterns.any? { |pattern| value.to_s.include?(pattern) }
    end

    # Check for XSS patterns
    xss_patterns = %w[
      <script> alert('xss') </script>
      onclick=alert('xss')
      &lt;script&gt; alert('xss') &lt;/script&gt;
    ]

    xss_injections = config.select do |key, value|
      xss_patterns.any? { |pattern| value.to_s.include?(pattern) }
    end

    # Check for command injection patterns
    cmd_patterns = %w[
      ; rm -rf /
      | wc -l
      `ls`
      && echo 'xss'
    ]

    cmd_injections = config.select do |key, value|
      cmd_patterns.any? { |pattern| value.to_s.include?(pattern) }
    end

    @results << {
      type: :sql,
      findings: sql_injections
    } if !sql_injections.empty?

    @results << {
      type: :xss,
      findings: xss_injections
    } if !xss_injections.empty?

    @results << {
      type: :cmd,
      findings: cmd_injections
    } if !cmd_injections.empty?
  end

  def parse_config(input)
    # Simulate parsing of a config file or codebase into a hash
    YAML.safe_load(input) || {}
  end

  def output_results
    puts "\nInjection Detector Results:"
    @results.each do |result|
      puts "  #{result[:type].upcase}:"
      result[:findings].each do |key, value|
        puts "    Key: #{key}, Value: #{value}"
      end
    end
  end
end

# Entry point for demo
if __FILE__ == $0
  input = <<~CONFIG
    ---
    database:
      connection_string: "postgres://user:pass@localhost:5432/db?sslmode=disable"
      query: "SELECT * FROM users WHERE id = #{id}"
    config:
      secret_key: "supersecretkey"
      log_level: "debug"
      xss_test: "<script>alert('xss')</script>"
      cmd_test: "echo 'hello'; rm -rf /tmp/test"
  CONFIG

  detector = InjectionDetector.new(input)
  detector.run
end