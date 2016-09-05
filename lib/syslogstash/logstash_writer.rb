require_relative 'worker'

# Write messages to one of a collection of logstash servers.
#
class Syslogstash::LogstashWriter
	include Syslogstash::Worker

	# Create a new logstash writer.
	#
	# Give it a list of servers, and your writer will be ready to go.
	# No messages will actually be *delivered*, though, until you call #run.
	#
	def initialize(servers, backlog, metrics)
		@servers, @backlog, @metrics = servers.map { |s| URI(s) }, backlog, metrics

		unless @servers.all? { |url| url.scheme == 'tcp' }
			raise ArgumentError,
					"Unsupported URL scheme: #{@servers.select { |url| url.scheme != 'tcp' }.join(', ')}"
		end

		@entries = []
		@entries_mutex = Mutex.new
	end

	# Add an entry to the list of messages to be sent to logstash.  Actual
	# message delivery will happen in a worker thread that is started with
	# #run.
	#
	def send_entry(e)
		@entries_mutex.synchronize do
			@entries << { content: e, arrival_timestamp: Time.now }
			@entries.shift while @entries.length > @backlog
		end
		@worker.run if @worker
	end

	# Start sending messages to logstash servers.  This method will return
	# almost immediately, and actual message sending will occur in a
	# separate worker thread.
	#
	def run
		@worker = Thread.new { send_messages }
	end

	private

	def send_messages
		loop do
			if @entries_mutex.synchronize { @entries.empty? }
				sleep 1
			else
				begin
					entry = @entries_mutex.synchronize { @entries.shift }

					current_server do |s|
						s.puts entry[:content]
					end

					@metrics.sent(@servers.last, entry[:arrival_timestamp])

					# If we got here, we sent successfully, so we don't want
					# to put the entry back on the queue in the ensure block
					entry = nil
				rescue StandardError => ex
					log { "Unhandled exception: #{ex.message} (#{ex.class})" }
					$stderr.puts ex.backtrace.map { |l| "  #{l}" }.join("\n")
				ensure
					@entries_mutex.synchronize { @entries.unshift if entry }
				end
			end
		end
	end

	# *Yield* a TCPSocket connected to the server we currently believe to
	# be accepting log entries, so that something can send log entries to
	# it.
	#
	# The yielding is very deliberate: it allows us to centralise all
	# error detection and handling within this one method, and retry
	# sending just by calling `yield` again when we've connected to
	# another server.
	#
	def current_server
		# I could handle this more cleanly with recursion, but I don't want
		# to fill the stack if we have to retry a lot of times
		done = false

		until done
			if @current_server
				begin
					debug { "Using current server" }
					yield @current_server
					done = true
				rescue SystemCallError => ex
					# Something went wrong during the send; disconnect from this
					# server and recycle
					debug { "Error while writing to current server: #{ex.message} (#{ex.class})" }
					@current_server.close
					@current_server = nil
					sleep 0.1
				end
			else
				begin
					# Rotate the next server onto the back of the list
					next_server = @servers.shift
					debug { "Trying to connect to #{next_server.to_s}" }
					@servers.push(next_server)
					@current_server = TCPSocket.new(next_server.host, next_server.port)
				rescue SystemCallError => ex
					# Connection failed for any number of reasons; try again
					debug { "Failed to connect to #{next_server.to_s}: #{ex.message} (#{ex.class})" }
					sleep 0.1
					retry
				end
			end
		end
	end
end
