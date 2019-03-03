require 'frankenstein/server'
require 'logger'

class Syslogstash::PrometheusExporter
  attr_reader :thread

  def initialize(cfg)
    @stats_server = Frankenstein::Server.new(port: 9159, logger: cfg.logger, metrics_prefix: "syslogstash_server")

    @msg_in  = prom.counter(:syslogstash_messages_received_total, "The number of syslog messages received from the log socket")
    @msg_out = prom.counter(:syslogstash_messages_sent_total, "The number of logstash messages sent to each logstash server")
    @lag     = prom.gauge(:syslogstash_last_relayed_message_timestamp, "When the last message that was successfully relayed to logstash was originally received")
    @queue   = prom.gauge(:syslogstash_queue_size, "How many messages are currently in the queue to be sent")
    @dropped = prom.counter(:syslogstash_messages_dropped, "How many messages have been dropped from the backlog queue")

    @q_mutex = Mutex.new

    @lag.set({}, 0)
    @queue.set({}, 0)
  end

  def received(socket)
    @msg_in.increment(socket_path: socket)
    @q_mutex.synchronize { @queue.set({}, @queue.get({}) + 1) }
  end

  def sent(server, stamp)
    @msg_out.increment(logstash_server: server)
    @q_mutex.synchronize { @queue.set({}, @queue.get({}) - 1) }
    @lag.set({}, stamp.to_f)
  end

  def dropped
    @queue.set({}, @queue.get({}) - 1)
    @dropped.increment({})
  end

  def run
    @stats_server.run
  end

  private

  def prom
    @stats_server.registry
  end
end
