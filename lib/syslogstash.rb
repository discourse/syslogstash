require 'uri'
require 'socket'
require 'json'
require 'thwait'
require 'logstash_writer'

# Read syslog messages from one or more sockets, and send it to a logstash
# server.
#
class Syslogstash
  def initialize(cfg)
    @cfg    = cfg
    @stats  = PrometheusExporter.new(cfg)
    @writer = LogstashWriter.new(server_name: cfg.logstash_server, backlog: cfg.backlog_size, logger: cfg.logger, metrics_registry: @stats.__send__(:prom))
    @reader = SyslogReader.new(cfg, @writer, @stats)
    @logger = cfg.logger
  end

  def run
    if @cfg.stats_server
      @logger.debug("main") { "Running stats server" }
      @stats.run
    end

    @writer.run

	 begin
      @reader.run.join
    rescue Exception => ex
      @logger.error("main") { (["Reader thread crashed: #{ex.message} (#{ex.class})"] + ex.backtrace).join("\n  ") }
    end

    exit 1
  end

  def force_disconnect!
    @writer.force_disconnect!
  end
end

require_relative 'syslogstash/config'
require_relative 'syslogstash/syslog_reader'
require_relative 'syslogstash/prometheus_exporter'
