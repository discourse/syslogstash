# frozen_string_literal: true
require 'uri'
require 'socket'
require 'json'

require 'service_skeleton'

# Read syslog messages from one or more sockets, and send it to a logstash
# server.
#
class Syslogstash
  include ServiceSkeleton

  string    :SYSLOGSTASH_LOGSTASH_SERVER
  string    :SYSLOGSTASH_SYSLOG_SOCKET, match: %r{\A(/.*|(tcp|udp|tcp\+udp)/\d+)\z}
  string    :SYSLOGSTASH_RELAY_TO_STDOUT, default: false
  string    :SYSLOGSTASH_DROP_REGEX, default: nil
  integer   :SYSLOGSTASH_BACKLOG_SIZE, default: 1_000_000, range: 0..(2**31-1)
  path_list :SYSLOGSTASH_RELAY_SOCKETS, default: []
  kv_list   :SYSLOGSTASH_ADD_FIELDS, default: {}, key_pattern: /\ASYSLOGSTASH_ADD_FIELD_(.*)\z/

  counter :syslogstash_messages_received_total,        docstring: "The number of syslog messages received from the log socket", labels: [:socket_path]
  counter :syslogstash_messages_sent_total,            docstring: "The number of logstash messages sent to each logstash server"
  counter :syslogstash_dropped_total,                  docstring: "Number of log entries that were not forwarded due to matching the drop regex"
  gauge   :syslogstash_last_relayed_message_timestamp, docstring: "When the last message that was successfully relayed to logstash was originally received"

  hook_signal("URG") do
    config.relay_to_stdout = !config.relay_to_stdout
    logger.info(logloc) { "SIGURG received; relay_to_stdout is now #{config.relay_to_stdout.inspect}" }
  end

  def self.register_ultravisor_children(ultravisor, config:, metrics_registry:)
    ultravisor.add_child(
      id: :syslogstash_logstash_writer,
      klass: LogstashWriter,
      method: :run,
      args: [server_name: config.logstash_server, backlog: config.backlog_size, logger: config.logger, metrics_registry: metrics_registry, metrics_prefix: :syslogstash_writer],
      shutdown: { 
        method: :shutdown,
        timeout: 10,
      }
    )

    writer = ultravisor[:syslogstash_logstash_writer]

    ultravisor.add_child(
      id: :syslog_reader,
      klass: SyslogReader,
      method: :run,
      args: [config, writer, metrics_registry],
      shutdown: {
        method: :shutdown,
        timeout: 1,
      }
    )
  end
end

require_relative 'syslogstash/syslog_reader'
