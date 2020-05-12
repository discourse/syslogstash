# frozen_string_literal: true
# A single socket reader.
#
class Syslogstash::SyslogReader
  include ServiceSkeleton::BackgroundWorker

  class UnparseableMessage < StandardError; end

  def initialize(config, logstash, metrics)
    @config, @logstash, @metrics = config, logstash, metrics

    @logger = config.logger

    @shutdown_reader, @shutdown_writer = IO.pipe

    @tcp_socket = nil
    @udp_socket = nil
    @unix_socket = nil

    super
    logger.debug(logloc) { "initialized" }
  end

  # Start reading from the socket, parsing entries, and flinging
  # them at logstash.
  def start
    logger.debug(logloc) { "off we go!" }

    begin
      if config.syslog_socket.start_with? 'tcp+udp/'
        port = config.syslog_socket.slice(8..).to_i # lop off tcp+udp/
        start_tcp(port)
        start_udp(port)
      elsif config.syslog_socket.start_with? 'tcp/'
        port = config.syslog_socket.slice(4..).to_i # lop off tcp/
        start_tcp(port)
      elsif config.syslog_socket.start_with? 'udp/'
        port = config.syslog_socket.slice(4..).to_i # lop off udp/
        start_udp(port)
      elsif config.syslog_socket.start_with? '/' # treat as a filename
        start_unix(config.syslog_socket)
      else
        raise ArgumentError, "invalid syslog specification: #{config.syslog_socket}"
      end
    rescue ArgumentError
      raise
    rescue StandardError => ex
      raise ex.class, "Error while trying to bind to #{config.syslog_socket}: #{ex.message}", ex.backtrace
    end

    interesting_sockets = [@shutdown_reader, @unix_socket, @udp_socket, @tcp_socket].compact
    # list of connected clients
    tcp_connected_fds = []

    begin
      while !@shutdown_reader.closed? do
        IO.select(interesting_sockets + tcp_connected_fds, nil, nil).first.each do |fd|
          if fd == @udp_socket || fd == @unix_socket
            begin
              msg = fd.recvmsg_nonblock
            rescue IO::WaitWritable
              logger.debug(logloc) { "select said a message was waiting, but it wasn't.  o.O" }
            else
              logger.debug(logloc) { "Message received: #{msg.inspect}" }
              process_message msg.first
            end
          elsif fd == @tcp_socket
            # a new connection has arrived
            client = StreamSocket.new(fd.accept, logger)
            tcp_connected_fds << client
            logger.debug(logloc) { "accepted connection on #{client}" }
          elsif tcp_connected_fds.include? fd
            # data incoming from existing tcp socket
            fd.read_messages do |message|
              logger.debug(logloc) { "Message received: #{message.inspect}" }
              process_message message
            end
            if fd.finished?
              fd.close
              tcp_connected_fds.delete fd
            end
          elsif fd == @shutdown_reader
            @shutdown_reader.close
            logger.debug(logloc) { "Tripped over shutdown reader" }
          end
        end
      end
    ensure
      # close all of our sockets
      if !@tcp_socket.nil?
        @tcp_socket.close
        logger.debug(logloc) { "closed stream socket #{config.syslog_socket}" }
      end
      if !@udp_socket.nil?
        @udp_socket.close
        logger.debug(logloc) { "closed datagram socket #{config.syslog_socket}" }
      end
      if !@unix_socket.nil?
        @unix_socket.close
        logger.debug(logloc) { "removing socket file #{config.syslog_socket}" }
        File.unlink(config.syslog_socket) rescue nil
      end

      # close all our TCP connections, if any
      tcp_connected_fds.each do |fd|
        fd.read_messages(final: true) do |message|
          logger.debug(logloc) { "Message received: #{message.inspect}" }
          process_message message
        end
        logger.debug(logloc) { "(shutting down) closing connection #{fd}" }
        fd.close
      end
      logger.debug(logloc) { "shutdown complete" }
    end
  end

  def shutdown
    @shutdown_writer.close
  end

  private

  attr_reader :config, :logger

  def start_tcp(port)
    begin
      @tcp_socket&.close
      @tcp_socket = TCPServer.new('::', port)
      logger.info(logloc) { "started TCP server on port #{port}" }
    rescue Errno::EADDRINUSE
      logger.info(logloc) { "tcp socket for #{config.syslog_socket} already in use" }
      sleep 1
      retry
    end
  end

  def start_udp(port)
    begin
      @udp_socket&.close
      @udp_socket = Socket.new(Socket::AF_INET6, Socket::SOCK_DGRAM, 0)
      @udp_socket.bind(Socket.pack_sockaddr_in(port, '::' ))
      logger.info(logloc) { "started UDP server on port #{port}" }
    rescue Errno::EADDRINUSE
      logger.info(logloc) { "udp socket for #{config.syslog_socket} already in use" }
      sleep 1
      retry
    end
  end

  def start_unix(path)
    begin
      @unix_socket&.close
      @unix_socket = Socket.new(Socket::AF_UNIX, Socket::SOCK_DGRAM, 0)
      @unix_socket.bind(Socket.pack_sockaddr_un(path))
      logger.info(logloc) { "started UNIX listener on #{config.syslog_socket}" }
      File.chmod(0666, path)
    rescue Errno::EEXIST, Errno::EADDRINUSE
      logger.info(logloc) { "socket #{config.syslog_socket} already exists; deleting" }
      File.unlink(config.syslog_socket) rescue nil
      retry
    end
  end

  def process_message(msg)
    @metrics.messages_received_total.increment(socket_path: config.syslog_socket)
    relay_message msg
    logstash_message msg
  end

  def extract_log_entry_from_message(msg)
    if msg =~ /\A<(\d+)>(\w{3} [ 0-9]{2} [0-9:]{8}) (.*)\z/m
      # most everything except our special snowflake: Cisco
      flags     = $1.to_i
      timestamp = $2
      content   = $3

      # Lo! the many ways that syslog messages can be formatted
      hostname, program, pid, message =
        case content
        # the gold standard: hostname, program name with optional PID
        when /\A([a-zA-Z0-9._-]*[^:]) (\S+?)(\[(\d+)\])?: (.*)\z/m
          [$1, $2, $4, $5]
        # hostname, no program name
        when /\A([a-zA-Z0-9._-]+) (\S+[^:] .*)\z/m
          [$1, nil, nil, $2]
        # program name, no hostname (yeah, you heard me, non-RFC compliant!)
        when /\A(\S+?)(\[(\d+)\])?: (.*)\z/m
          [nil, $1, $3, $4]
        else
          # I have NFI
          [nil, nil, nil, content]
        end

      log_entry(
        syslog_timestamp: timestamp,
        severity:         flags % 8,
        facility:         flags / 8,
        hostname:         hostname,
        program:          program,
        pid:              pid.nil? ? nil : pid.to_i,
        message:          message,
      )
    elsif msg =~ /\A<(\d+)>(\d+): (?:([^ :]+): )?(\w{3} [ 0-9]{2} [0-9:]{8}\.[0-9]{3}): (.*)\z/m
      # aforementioned special snowflake: Cisco IOS
      # e.g.: <157>6223: switch01.sjc3: Sep 16 18:35:06.954: %PARSER-5-CFGLOG_LOGGEDCMD: command
      flags     = $1.to_i
      seq_num   = $2
      hostname  = $3 # optional
      timestamp = $4
      content   = $5

      program, message =
        case content
        # IOS: %ID: details
        when /\A%([^:]+): (.*)\z/m
          [$1, $2]
        else
          # I have NFI
          [nil, content]
        end

      log_entry(
        syslog_timestamp: timestamp,
        severity:         flags % 8,
        facility:         flags / 8,
        hostname:         hostname,
        program:          program,
        pid:              nil,
        message:          message,
        #seq_num:          seq_num, # (deliberately leaving this noise out)
      )
    else
      raise UnparseableMessage
    end
  end

  def logstash_message(msg)
    msg = msg.chomp.encode("UTF-8", invalid: :replace, undef: :replace)
    begin
      log_entry = extract_log_entry_from_message(msg)
      if config.drop_regex && log_entry[:message].match?(config.drop_regex)
        @metrics.dropped_total.increment({})
        logger.debug(logloc) { "dropping message #{msg}" }
        return
      end
      @logstash.send_event(log_entry)
    rescue UnparseableMessage
      logger.warn(logloc) { "Unparseable message: #{msg.inspect}" }
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

      logger.debug(logloc) { "Complete log entry is: #{e.inspect}" }
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
          logger.warn(logloc) { "Error while connecting to relay socket #{f}: #{ex.message} (#{ex.class})" }
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
          logger.info(logloc) { "Error on socket #{f} has cleared; messages are being delivered again" }
          @currently_failed[f] = false
        end
      rescue Errno::ENOTCONN
        unless @currently_failed[f]
          logger.debug(logloc) { "Nothing is listening on socket #{f}" }
          @currently_failed[f] = true
        end
      rescue IO::EAGAINWaitWritable
        unless @currently_failed[f]
          logger.warn(logloc) { "Socket #{f} is currently backlogged; messages to this socket are now being discarded undelivered" }
          @currently_failed[f] = true
        end
      rescue StandardError => ex
        logger.warn(logloc) { (["Failed to relay message to socket #{f} from #{config.syslog_socket}: #{ex.message} (#{ex.class})"] + ex.backtrace).join("\n  ") }
      end
    ensure
      s.close
    end
  end

  # There is a gap between 12-15 inclusive
  # We need to define them to ensure the local0-7 facilities line up correctly
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
    facility12
    facility13
    facility14
    facility15
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

require_relative 'syslog_reader/stream_socket'
