# polyglot/ruby/session_monitor.rb

require 'socket'
require 'thread'

class SessionMonitor
  attr_reader :sessions, :logger

  def initialize(logger = Logger.new(STDOUT))
    @logger = logger
    @sessions = {}
    @lock = Mutex.new
    @stop_flag = false
  end

  def start(port = 9292)
    @logger.info("Starting Session Monitor on port #{port}")
    server = TCPServer.new(port)

    loop do
      break if @stop_flag

      Thread.start do
        client = server.accept
        session_id = generate_session_id
        @lock.synchronize do
          @sessions[session_id] = { client: client, active: true, timestamp: Time.now }
          @logger.info("New session started: #{session_id}")
        end

        begin
          while active?(session_id)
            data = client.gets
            break unless data

            process_data(session_id, data)
          end
        rescue => e
          @logger.error("Session #{session_id} error: #{e.message}")
        ensure
          close_session(session_id)
        end
      end
    end
  end

  def stop
    @stop_flag = true
    @logger.info("Stopping Session Monitor")
  end

  private

  def generate_session_id
    "sess_#{SecureRandom.uuid}"
  end

  def active?(session_id)
    @lock.synchronize do
      session = @sessions[session_id]
      return false unless session && session[:active]
      session[:timestamp] = Time.now
      true
    end
  end

  def process_data(session_id, data)
    @logger.debug("Received data in session #{session_id}: #{data}")
    # Simulate credential check, injection detection, and reach assessment
    if data.include?("admin") && data.include?("inject")
      @logger.warn("Potential lethal trifecta detected in session #{session_id}")
    end
  end

  def close_session(session_id)
    @lock.synchronize do
      session = @sessions[session_id]
      return unless session && session[:active]

      session[:active] = false
      session[:client].close if session[:client]
      @logger.info("Session #{session_id} closed")
    end
  end
end

# Entry point for demo
if __FILE__ == $0
  logger = Logger.new(STDOUT)
  logger.level = Logger::INFO

  monitor = SessionMonitor.new(logger)
  begin
    monitor.start(9292)
  rescue Interrupt
    monitor.stop
    logger.info("Session Monitor exited gracefully")
  end
end