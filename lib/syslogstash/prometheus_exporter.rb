require 'prometheus/client/rack/exporter'
require 'rack'
require 'rack/handler/webrick'
require 'logger'

class Syslogstash::PrometheusExporter
	attr_reader :thread

	def initialize
		@msg_in  = prom.counter(:syslogstash_messages_received, "The number of syslog messages received from each log socket")
		@msg_out = prom.counter(:syslogstash_messages_sent, "The number of logstash messages sent to each logstash server")
		@lag     = prom.gauge(:syslogstash_lag_ms, "How far behind we are in relaying messages")
		@queue   = prom.gauge(:syslogstash_queue_size, "How many messages are queued to be sent")
	end

	def received(socket, stamp)
		@msg_in.increment(socket_path: socket)
		@queue.set({}, (@queue.get({}) || 0) + 1)

		if @most_recent_received.nil? || @most_recent_received < stamp
			@most_recent_received = stamp

			refresh_lag
		end
	end

	def sent(server, stamp)
		@msg_out.increment(logstash_server: server)
		@queue.set({}, @queue.get({}) - 1)

		if @most_recent_sent.nil? || @most_recent_sent < stamp
			@most_recent_sent = stamp

			refresh_lag
		end
	end

	def run
		@thread = Thread.new do
			app = Rack::Builder.new
			app.use Prometheus::Client::Rack::Exporter
			app.run ->(env) { [404, {'Content-Type' => 'text/plain'}, ['Nope']] }

			logger = Logger.new($stderr)
			logger.level = Logger::INFO
			logger.formatter = proc { |s, t, p, m| "[Syslogstash::PrometheusExporter::WEBrick] #{m}\n" }

			Rack::Handler::WEBrick.run app, Host: '::', Port: 9159, Logger: logger, AccessLog: []
		end
	end

	private

	def prom
		Prometheus::Client.registry
	end

	def refresh_lag
		if @most_recent_received && @most_recent_sent
			@lag.set({}, ((@most_recent_received.to_f - @most_recent_sent.to_f) * 1000).to_i)
		end
	end
end
