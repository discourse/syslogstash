require 'resolv'
require 'ipaddr'

# Write messages to a logstash server.
#
class Syslogstash::LogstashWriter
	Target = Struct.new(:hostname, :port)

	attr_reader :thread

	# Create a new logstash writer.
	#
	# Once the object is created, you're ready to give it messages by
	# calling #send_entry.  No messages will actually be *delivered* to
	# logstash, though, until you call #run.
	#
	def initialize(cfg, stats)
		@server_name, @logger, @backlog, @stats = cfg.logstash_server, cfg.logger, cfg.backlog_size, stats

		@entries = []
		@entries_mutex = Mutex.new
		@cs_mutex = Mutex.new
	end

	# Add an entry to the list of messages to be sent to logstash.  Actual
	# message delivery will happen in a worker thread that is started with
	# #run.
	#
	def send_entry(e)
		@entries_mutex.synchronize do
			@entries << { content: e, arrival_timestamp: Time.now }
			while @entries.length > @backlog
				@entries.shift
				@stats.dropped
			end
		end

		@thread.run if @thread
	end

	# Start sending messages to logstash servers.  This method will return
	# almost immediately, and actual message sending will occur in a
	# separate thread.
	#
	def run
		@thread = Thread.new { send_messages }
	end

	# Cause the writer to disconnect from the currently-active server.
	#
	def force_disconnect!
		@cs_mutex.synchronize do
			@logger.info("writer") { "Forced disconnect from #{server_id(@current_server) }" }
			@current_server.close if @current_server
			@current_server = nil
		end
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
						@stats.sent(server_id(s), entry[:arrival_timestamp])
					end

					# If we got here, we sent successfully, so we don't want
					# to put the entry back on the queue in the ensure block
					entry = nil
				rescue StandardError => ex
					@logger.error("writer") { (["Unhandled exception while writing entry: #{ex.message} (#{ex.class})"] + ex.backtrace).join("\n  ") }
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
			@cs_mutex.synchronize do
				if @current_server
					begin
						@logger.debug("writer") { "Using current server #{server_id(@current_server)}" }
						yield @current_server
						done = true
					rescue SystemCallError => ex
						# Something went wrong during the send; disconnect from this
						# server and recycle
						@logger.debug("writer") { "Error while writing to current server: #{ex.message} (#{ex.class})" }
						@current_server.close
						@current_server = nil
						sleep 0.1
					end
				else
					candidates = resolve_server_name
					@logger.debug("writer") { "Server candidates: #{candidates.inspect}" }

					begin
						next_server = candidates.shift

						if next_server
							@logger.debug("writer") { "Trying to connect to #{next_server.to_s}" }
							@current_server = TCPSocket.new(next_server.hostname, next_server.port)
						else
							@logger.debug("writer") { "Could not connect to any server; pausing before trying again" }
							@current_server = nil
							sleep 5
						end
					rescue SystemCallError => ex
						# Connection failed for any number of reasons; try the next one in the list
						@logger.warn("writer") { "Failed to connect to #{next_server.to_s}: #{ex.message} (#{ex.class})" }
						sleep 0.1
						retry
					end
				end
			end
		end
	end

	def server_id(s)
		pa = s.peeraddr
		if pa[0] == "AF_INET6"
			"[#{pa[3]}]:#{pa[1]}"
		else
			"#{pa[3]}:#{pa[1]}"
		end
	end

	def resolve_server_name
		return [static_target] if static_target

		# The IPv6 literal case should have been taken care of by
		# static_target, so the only two cases we have to deal with
		# here are specified-port (assume A/AAAA) or no port (assume SRV).
		if @server_name =~ /:/
			host, port = @server_name.split(":", 2)
			addrs = Resolv::DNS.new.getaddresses(host)
			if addrs.empty?
				@logger.warn("writer") { "No addresses resolved for server_name #{host.inspect}" }
			end
			addrs.map { |a| Target.new(a.to_s, port.to_i) }
		else
			# SRV records ftw
			[].tap do |list|
				left = Resolv::DNS.new.getresources(@server_name, Resolv::DNS::Resource::IN::SRV)
				if left.empty?
					@logger.warn("writer") { "No SRV records found for server_name #{@server_name.inspect}" }
				end
				until left.empty?
					prio = left.map { |rr| rr.priority }.uniq.min
					candidates = left.select { |rr| rr.priority == prio }
					left -= candidates
					candidates.sort_by! { |rr| [rr.weight, rr.target.to_s] }
					until candidates.empty?
						selector = rand(candidates.inject(1) { |n, rr| n + rr.weight })
						chosen = candidates.inject(0) do |n, rr|
							break rr if n + rr.weight >= selector
							n + rr.weight
						end
						candidates.delete(chosen)
						list << Target.new(chosen.target.to_s, chosen.port)
					end
				end
			end
		end
	end

	def static_target
		@static_target ||= begin
			if @server_name =~ /\A(.*):(\d+)\z/
				begin
					Target.new(IPAddr.new($1).to_s, $2.to_i)
				rescue ArgumentError
					# Whatever is on the LHS isn't a recognisable address;
					# assume hostname and continue
					nil
				end
			end
		end
	end
end
