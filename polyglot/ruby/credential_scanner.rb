# polyglot/ruby/credential_scanner.rb

require 'yaml'
require 'json'
require 'fileutils'

class CredentialScanner
  def initialize(config_path = 'config.yaml')
    @config = YAML.load_file(config_path) || {}
    @scan_dirs = @config['scan_dirs'] || ['.', 'config', 'secrets']
    @output_file = @config['output_file'] || 'credentials_report.json'
    @exclude_patterns = @config['exclude_patterns'] || ['*.log', '*.tmp']
  end

  def run
    results = []
    scan_directories(@scan_dirs, results)
    write_report(results)
    puts "Credential scan completed. Report saved to #{@output_file}"
  end

  private

  def scan_directories(paths, results)
    paths.each do |path|
      next unless File.directory?(path)

      Dir.glob("#{path}/**/*") do |file|
        next if @exclude_patterns.any? { |pattern| file.match(pattern) }
        next unless File.file?(file)

        content = File.read(file)
        credentials = extract_credentials(content)
        results += credentials.map do |type, value|
          {
            type: type,
            value: value,
            file: file,
            line: content.lines.find_index { |line| line.include?(value) } + 1
          }
        end
      end
    end
  end

  def extract_credentials(content)
    credentials = []

    # Common credential patterns
    credentials += extract_pattern(content, /password\s*=\s*["']?([^"'\s]+)/i, 'password')
    credentials += extract_pattern(content, /secret\s*=\s*["']?([^"'\s]+)/i, 'secret')
    credentials += extract_pattern(content, /token\s*=\s*["']?([^"'\s]+)/i, 'token')
    credentials += extract_pattern(content, /key\s*=\s*["']?([^"'\s]+)/i, 'key')
    credentials += extract_pattern(content, /username\s*=\s*["']?([^"'\s]+)/i, 'username')
    credentials += extract_pattern(content, /password\s*:\s*([^,\s]+)/i, 'password')
    credentials += extract_pattern(content, /secret\s*:\s*([^,\s]+)/i, 'secret')
    credentials += extract_pattern(content, /token\s*:\s*([^,\s]+)/i, 'token')
    credentials += extract_pattern(content, /key\s*:\s*([^,\s]+)/i, 'key')
    credentials += extract_pattern(content, /username\s*:\s*([^,\s]+)/i, 'username')

    # JSON/YAML content
    if content.match?(/\A\s*{.*}\s*\z/) || content.match?(/\A\s*{.*}\s*\z/)
      begin
        data = JSON.parse(content)
        credentials += extract_from_hash(data, 'password', 'secret', 'token', 'key', 'username')
      rescue JSON::ParserError
        # Skip if not valid JSON
      end
    elsif content.match?(/\A\s*---\s*\z/) || content.match?(/\A\s*---\s*\z/)
      begin
        data = YAML.safe_load(content)
        credentials += extract_from_hash(data, 'password', 'secret', 'token', 'key', 'username')
      rescue Psych::SyntaxError
        # Skip if not valid YAML
      end
    end

    credentials
  end

  def extract_pattern(text, pattern, type)
    text.scan(pattern).flatten.map { |value| [type, value] }
  end

  def extract_from_hash(data, *types)
    result = []
    types.each do |type|
      if data.is_a?(Hash) && data.key?(type)
        result << [type, data[type]]
      elsif data.is_a?(Hash) && data.values.any? { |v| v.is_a?(Hash) }
        data.values.each do |sub_data|
          result += extract_from_hash(sub_data, *types)
        end
      end
    end
    result
  end

  def write_report(results)
    FileUtils.mkdir_p(File.dirname(@output_file))
    File.open(@output_file, 'w') do |f|
      f.write(JSON.pretty_generate(results))
    end
  end
end

if __FILE__ == $0
  scanner = CredentialScanner.new
  scanner.run
end