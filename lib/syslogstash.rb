require 'uri'
require 'socket'
require 'json'
require 'thwait'

# Read syslog messages from one or more sockets, and send it to a logstash
# server.
#
class Syslogstash
	def initialize(sockets, servers, backlog)
		@metrics = PrometheusExporter.new

		@writer = LogstashWriter.new(servers, backlog, @metrics)

		@readers = sockets.map { |f, tags| SyslogReader.new(f, tags, @writer, @metrics) }
	end

	def run
		@metrics.run
		@writer.run
		@readers.each { |w| w.run }

		tw = ThreadsWait.new(@metrics.thread, @writer.thread, *(@readers.map { |r| r.thread }))

		dead_thread = tw.next_wait

		if dead_thread == @writer.thread
			$stderr.puts "[Syslogstash] Writer thread crashed."
		elsif dead_thread == @metrics.thread
			$stderr.puts "[Syslogstash] Metrics exporter thread crashed."
		else
			reader = @readers.find { |r| r.thread == dead_thread }

			$stderr.puts "[Syslogstash] Reader thread for #{reader.file} crashed."
		end

		begin
			dead_thread.join
		rescue Exception => ex
			$stderr.puts "[Syslogstash] Exception in thread was: #{ex.message} (#{ex.class})"
			$stderr.puts ex.backtrace.map { |l| "  #{l}" }.join("\n")
		end

		exit 1
	end
end

require_relative 'syslogstash/syslog_reader'
require_relative 'syslogstash/logstash_writer'
require_relative 'syslogstash/prometheus_exporter'
