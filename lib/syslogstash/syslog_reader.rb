require_relative 'worker'

# A single socket reader.
#
class Syslogstash::SyslogReader
	include Syslogstash::Worker

	attr_reader :file

	def initialize(file, tags, logstash, metrics)
		@file, @tags, @logstash, @metrics = file, tags, logstash, metrics

		log { "initializing syslog socket #{file} with tags #{tags.inspect}" }
	end

	# Start reading from the socket file, parsing entries, and flinging
	# them at logstash.  This method will return, with the operation
	# continuing in a separate thread.
	#
	def run
		debug { "#run called" }

		begin
			socket = Socket.new(Socket::AF_UNIX, Socket::SOCK_DGRAM, 0)
			socket.bind(Socket.pack_sockaddr_un(@file))
		rescue Errno::EEXIST, Errno::EADDRINUSE
			log { "socket file #{@file} already exists; deleting" }
			File.unlink(@file) rescue nil
			retry
		rescue SystemCallError
			$stderr.puts "Error while trying to bind to #{@file}"
			raise
		end

		@worker = Thread.new do
			begin
				loop do
					msg = socket.recvmsg
					debug { "Message received: #{msg.inspect}" }
					@metrics.received(@file, Time.now)
					process_message msg.first.chomp
				end
			ensure
				socket.close
				log { "removing socket file #{@file}" }
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
			$stderr.puts "Unparseable message: #{msg}"
		end
	end

	def log_entry(h)
		{}.tap do |e|
			e['@version']   = '1'
			e['@timestamp'] = Time.now.utc.strftime("%FT%T.%LZ")

			h[:facility_name] = FACILITIES[h[:facility]]
			h[:severity_name] = SEVERITIES[h[:severity]]

			e.merge!(h.delete_if { |k,v| v.nil? })

			e.merge!(@tags) if @tags.is_a? Hash

			debug { "Log entry is: #{e.inspect}" }
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
