# A single socket reader.
#
class Syslogstash::SyslogReader
  include ServiceSkeleton::BackgroundWorker

  def initialize(config, logstash, metrics)
    @config, @logstash, @metrics = config, logstash, metrics

    @logger = config.logger

    @shutdown_reader, @shutdown_writer = IO.pipe

    super
  end

  # Start reading from the socket file, parsing entries, and flinging
  # them at logstash.
  #
  def start
    config.logger.debug(logloc) { "off we go!" }

    begin
      socket = Socket.new(Socket::AF_UNIX, Socket::SOCK_DGRAM, 0)
      socket.bind(Socket.pack_sockaddr_un(config.syslog_socket))
      File.chmod(0666, config.syslog_socket)
    rescue Errno::EEXIST, Errno::EADDRINUSE
      config.logger.info(logloc) { "socket file #{config.syslog_socket} already exists; deleting" }
      File.unlink(config.syslog_socket) rescue nil
      retry
    rescue StandardError => ex
      raise ex.class, "Error while trying to bind to #{config.syslog_socket}: #{ex.message}", ex.backtrace
    end

    begin
      loop do
        IO.select([@shutdown_reader, socket]).first.each do |fd|
          if fd == socket
            begin
              msg = socket.recvmsg_nonblock
            rescue IO::WaitWritable
              config.logger.debug(logloc) { "select said a message was waiting, but it wasn't.  o.O" }
            else
              config.logger.debug(logloc) { "Message received: #{msg.inspect}" }
              @metrics.messages_received_total.increment(socket_path: config.syslog_socket)
              @metrics.queue_size.increment({})
              relay_message msg.first
              process_message msg.first.chomp
            end
          elsif fd == @shutdown_reader
            @shutdown_reader.close
            config.logger.debug(logloc) { "Tripped over shutdown reader" }
            break
          end
        end
      end
    ensure
      socket.close
      config.logger.debug(logloc) { "removing socket file #{config.syslog_socket}" }
      File.unlink(config.syslog_socket) rescue nil
    end
  end

  def shutdown
    @shutdown_writer.close
  end

  private

  attr_reader :config, :logger

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

      if config.drop_regex && message && message.match?(config.drop_regex)
        @metrics.dropped_total.increment({})
        config.logger.debug(logloc) { "dropping message #{message}" }
        return
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
      )

      @logstash.send_event(log_entry)
    else
      config.logger.warn(logloc) { "Unparseable message: #{msg.inspect}" }
    end
  end

  def log_entry(h)
    {}.tap do |e|
      e['@version']   = '1'
      e['@timestamp'] = Time.now.utc.strftime("%FT%T.%LZ")

      h[:facility_name] = FACILITIES[h[:facility]]
      h[:severity_name] = SEVERITIES[h[:severity]]

      e.merge!(h.delete_if { |k,v| v.nil? })
      e.merge!(config.add_fields)

      config.logger.debug(logloc) { "Complete log entry is: #{e.inspect}" }
    end
  end

  def relay_message(msg)
    @currently_failed ||= {}

    if config.relay_to_stdout
      # This one's easy
      puts msg.sub(/\A<\d+>/, '')
      $stdout.flush
    end

    config.relay_sockets.each do |f|
      relay_to_socket(f)
    end
  end

  def relay_to_socket(f)
    begin
      s = Socket.new(Socket::AF_UNIX, Socket::SOCK_DGRAM, 0)
      begin
        s.connect(Socket.pack_sockaddr_un(f))
      rescue Errno::ENOENT
        # Socket doesn't exist; we don't care enough about this to bother
        # reporting it.  People will figure it out themselves soon enough.
      rescue StandardError => ex
        unless @currently_failed[f]
          config.logger.warn(logloc) { "Error while connecting to relay socket #{f}: #{ex.message} (#{ex.class})" }
          @currently_failed[f] = true
        end
        return
      end

      begin
        # We really, *really* don't want to block the world just because
        # whoever's on the other end of the relay socket can't process
        # messages quick enough.
        s.sendmsg_nonblock(msg)
        if @currently_failed[f]
          config.logger.info(logloc) { "Error on socket #{f} has cleared; messages are being delivered again" }
          @currently_failed[f] = false
        end
      rescue Errno::ENOTCONN
        unless @currently_failed[f]
          config.logger.debug(logloc) { "Nothing is listening on socket #{f}" }
          @currently_failed[f] = true
        end
      rescue IO::EAGAINWaitWritable
        unless @currently_failed[f]
          config.logger.warn(logloc) { "Socket #{f} is currently backlogged; messages to this socket are now being discarded undelivered" }
          @currently_failed[f] = true
        end
      rescue StandardError => ex
        config.logger.warn(logloc) { (["Failed to relay message to socket #{f} from #{config.syslog_socket}: #{ex.message} (#{ex.class})"] + ex.backtrace).join("\n  ") }
      end
    ensure
      s.close
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
