require 'uri'
require 'socket'
require 'json'
require 'thwait'

# Read syslog messages from one or more sockets, and send it to a logstash
# server.
#
class Syslogstash
	def initialize(cfg)
		@cfg    = cfg
		@stats  = PrometheusExporter.new(cfg)
		@writer = LogstashWriter.new(cfg, @stats)
		@reader = SyslogReader.new(cfg, @writer, @stats)
		@logger = cfg.logger
	end

	def run
		if @cfg.stats_server
			@logger.debug("main") { "Running stats server" }
			@stats.run
		end

		@writer.run
		@reader.run

		dead_thread = ThreadsWait.new(@reader.thread, @writer.thread).next_wait

		if dead_thread == @writer.thread
			@logger.error("main") { "Writer thread crashed." }
		elsif dead_thread == @reader.thread
			@logger.error("main") { "Reader thread crashed." }
		else
			@logger.fatal("main") { "ThreadsWait#next_wait returned unexpected value #{dead_thread.inspect}" }
			exit 1
		end

		begin
			dead_thread.join
		rescue Exception => ex
			@logger.error("main") { (["Exception in crashed thread was: #{ex.message} (#{ex.class})"] + ex.backtrace).join("\n  ") }
		end

		exit 1
	end
end

require_relative 'syslogstash/config'
require_relative 'syslogstash/syslog_reader'
require_relative 'syslogstash/logstash_writer'
require_relative 'syslogstash/prometheus_exporter'
