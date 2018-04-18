# A single socket reader.
#
class Syslogstash::SyslogReader
	attr_reader :thread

	def initialize(cfg, logstash, stats)
		@file, @logstash, @stats = cfg.syslog_socket, logstash, stats

		@add_fields = cfg.add_fields
		@relay_to   = cfg.relay_sockets
		@cfg        = cfg
		@logger     = cfg.logger
	end

	# Start reading from the socket file, parsing entries, and flinging
	# them at logstash.  This method will return, with the operation
	# continuing in a separate thread.
	#
	def run
		@logger.debug("reader") { "#run called" }

		begin
			socket = Socket.new(Socket::AF_UNIX, Socket::SOCK_DGRAM, 0)
			socket.bind(Socket.pack_sockaddr_un(@file))
			File.chmod(0666, @file)
		rescue Errno::EEXIST, Errno::EADDRINUSE
			@logger.info("reader") { "socket file #{@file} already exists; deleting" }
			File.unlink(@file) rescue nil
			retry
		rescue StandardError => ex
			raise ex.class, "Error while trying to bind to #{@file}: #{ex.message}", ex.backtrace
		end

		@thread = Thread.new do
			begin
				loop do
					msg = socket.recvmsg
					@logger.debug("reader") { "Message received: #{msg.inspect}" }
					@stats.received(@file)
					relay_message msg.first
					process_message msg.first.chomp
				end
			ensure
				socket.close
				@logger.debug("reader") { "removing socket file #{@file}" }
				File.unlink(@file) rescue nil
			end
		end
	end

	private

	def process_message(msg)
		if msg =~ /^<(\d+)>(\w{3} [ 0-9]{2} [0-9:]{8}) (.*)$/
			flags     = $1.to_i
			timestamp = $2
			content   = $3

			# Lo! the many ways that syslog messages can be formatted
			hostname, program, pid, message = case content
				# the gold standard: hostname, program name with optional PID
				when /^([a-zA-Z0-9._-]*[^:]) (\S+?)(\[(\d+)\])?: (.*)$/
					[$1, $2, $4, $5]
				# hostname, no program name
				when /^([a-zA-Z0-9._-]+) (\S+[^:] .*)$/
					[$1, nil, nil, $2]
				# program name, no hostname (yeah, you heard me, non-RFC compliant!)
				when /^(\S+?)(\[(\d+)\])?: (.*)$/
					[nil, $1, $3, $4]
				else
					# I have NFI
					[nil, nil, nil, content]
			end

			severity = flags % 8
			facility = flags / 8

			log_entry = log_entry(
				syslog_timestamp: timestamp,
				severity:         severity,
				facility:         facility,
				hostname:         hostname,
				program:          program,
				pid:              pid.nil? ? nil : pid.to_i,
				message:          message,
			).to_json

			@logstash.send_entry(log_entry)
		else
			@logger.warn("reader") { "Unparseable message: #{msg.inspect}" }
		end
	end

	def log_entry(h)
		{}.tap do |e|
			e['@version']   = '1'
			e['@timestamp'] = Time.now.utc.strftime("%FT%T.%LZ")

			h[:facility_name] = FACILITIES[h[:facility]]
			h[:severity_name] = SEVERITIES[h[:severity]]

			e.merge!(h.delete_if { |k,v| v.nil? })
			e.merge!(@add_fields)

			@logger.debug("reader") { "Complete log entry is: #{e.inspect}" }
		end
	end

	def relay_message(msg)
		@currently_failed ||= {}

		if @cfg.relay_to_stdout
			# This one's easy
			puts msg.sub(/\A<\d+>/, '')
		end

		@relay_to.each do |f|
			s = Socket.new(Socket::AF_UNIX, Socket::SOCK_DGRAM, 0)
			begin
				s.connect(Socket.pack_sockaddr_un(f))
			rescue Errno::ENOENT
				# Socket doesn't exist; we don't care enough about this to bother
				# reporting it.  People will figure it out themselves soon enough.
			rescue StandardError => ex
				unless @currently_failed[f]
					@logger.warn("reader") { "Error while connecting to relay socket #{f}: #{ex.message} (#{ex.class})" }
					@currently_failed[f] = true
				end
				next
			end

			begin
				# We really, *really* don't want to block the world just because
				# whoever's on the other end of the relay socket can't process
				# messages quick enough.
				s.sendmsg_nonblock(msg)
				if @currently_failed[f]
					@logger.info("reader") { "Error on socket #{f} has cleared; messages are being delivered again" }
					@currently_failed[f] = false
				end
			rescue Errno::ENOTCONN
				unless @currently_failed[f]
					@logger.debug("reader") { "Nothing is listening on socket #{f}" }
					@currently_failed[f] = true
				end
			rescue IO::EAGAINWaitWritable
				unless @currently_failed[f]
					@logger.warn("reader") { "Socket #{f} is currently backlogged; messages to this socket are now being discarded undelivered" }
					@currently_failed[f] = true
				end
			rescue StandardError => ex
				@logger.warn("reader") { (["Failed to relay message to socket #{f} from #{@file}: #{ex.message} (#{ex.class})"] + ex.backtrace).join("\n  ") }
			end
		end
	end

	FACILITIES = %w{
		kern
		user
		mail
		daemon
		auth
		syslog
		lpr
		news
		uucp
		cron
		authpriv
		ftp
		local0 local1 local2 local3 local4 local5 local6 local7
	}

	SEVERITIES = %w{
		emerg
		alert
		crit
		err
		warning
		notice
		info
		debug
	}
end
