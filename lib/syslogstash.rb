# frozen_string_literal: true
require 'uri'
require 'socket'
require 'json'

require 'logstash_writer'
require 'service_skeleton'

# Read syslog messages from one or more sockets, and send it to a logstash
# server.
#
class Syslogstash < ServiceSkeleton
  string    :SYSLOGSTASH_LOGSTASH_SERVER
  string    :SYSLOGSTASH_SYSLOG_SOCKET, match: %r{\A(/.*|(tcp|udp|tcp\+udp)/\d+)\z}
  string    :SYSLOGSTASH_RELAY_TO_STDOUT, default: false
  string    :SYSLOGSTASH_DROP_REGEX, default: nil
  integer   :SYSLOGSTASH_BACKLOG_SIZE, default: 1_000_000, range: 0..(2**31-1)
  path_list :SYSLOGSTASH_RELAY_SOCKETS, default: []
  kv_list   :SYSLOGSTASH_ADD_FIELDS, default: {}, key_pattern: /\ASYSLOGSTASH_ADD_FIELD_(.*)\z/

  def initialize(*_)
    super

    hook_signal("URG") do
      config.relay_to_stdout = !config.relay_to_stdout
      logger.info(logloc) { "SIGURG received; relay_to_stdout is now #{config.relay_to_stdout.inspect}" }
    end

    @shutdown_reader, @shutdown_writer = IO.pipe

    metrics.counter(:syslogstash_messages_received_total, "The number of syslog messages received from the log socket")
    metrics.counter(:syslogstash_messages_sent_total, "The number of logstash messages sent to each logstash server")
    metrics.gauge(:syslogstash_last_relayed_message_timestamp, "When the last message that was successfully relayed to logstash was originally received")
    metrics.counter(:syslogstash_dropped_total, "Number of log entries that were not forwarded due to matching the drop regex")

    @writer = LogstashWriter.new(server_name: config.logstash_server, backlog: config.backlog_size, logger: config.logger, metrics_registry: metrics)
    @reader = SyslogReader.new(config, @writer, metrics)
  end

  def run
    @writer.start!
    @reader.start!

    @shutdown_reader.getc
    @shutdown_reader.close
  end

  def shutdown
    @reader.stop!
    @writer.stop!

    @shutdown_writer.close
  end

  def force_disconnect!
    @writer.force_disconnect!
  end
end

require_relative 'syslogstash/syslog_reader'
